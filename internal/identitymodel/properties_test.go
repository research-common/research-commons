package identitymodel

import (
	"fmt"
	"github.com/research-common/research-commons/internal/conformance"
	"math/rand"
	"reflect"
	"slices"
	"strings"
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
	conformance.Partial(t, "C-id-12", "seeded model property over facts, not signed bytes; the production reader asks this evaluator, but this case is not yet run through a command")
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
	conformance.Partial(t, "C-id-15", "seeded model property; consumer noninterference is not built")
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

// TestSeededEvidenceNeverRaisesStatus: monotonicity over the shapes the table tests cover one at a time. From a
// generated delegate DAG, each step adds one fact of a random shape: a terminal root event, a rival inception
// (and events under it), a root fork, a root merge, a cut placed before its grant on a root fork (prev = I), a
// cut with a missing or wrong-lineage prev, an unsupported or invalid root line, a sibling grant, a second
// identity granting the same K, a delegate self-event, a K line with a missing link, a root event with a
// rejected signature, an unsupported sibling grant, or an ordinary cut. No step supplies an id earlier evidence
// named as missing, so no status may rise (denied < unknown < eligible) for any statement.
func TestSeededEvidenceNeverRaisesStatus(t *testing.T) {
	conformance.Partial(t, "C-id-12", "seeded monotonicity over model facts for fourteen evidence shapes; signed bytes and consumers are not covered")
	rank := map[Status]int{Denied: 0, Unknown: 1, Eligible: 2}
	moves := map[string]int{}
	for seed := int64(1); seed <= 150; seed++ {
		fs, candidates, _ := generatedDAG(seed)
		rng := rand.New(rand.NewSource(seed + 50000))
		seqOf := map[ID]uint64{"I": 0, "G": 1}
		root := []ID{"I", "G"}
		var rival []ID
		n := 0
		fresh := func(p string) ID { n++; return ID(fmt.Sprintf("%s-%d", p, n)) }
		rootLine := func(event Event) Fact {
			prev := root[rng.Intn(len(root))]
			f := line(fresh("r"), "R", seqOf[prev]+1, prev, event)
			return f
		}
		pick := func() ID { return candidates[rng.Intn(len(candidates))] }
		before := snapshot(t, fs)
		for step := 0; step < 8; step++ {
			var add []Fact
			switch shape := rng.Intn(15); shape {
			case 0: // terminal root event
				add = append(add, rootLine([]Event{RotateKey, RevokeKey}[rng.Intn(2)]))
			case 1: // rival inception by R, with an event under it
				ri := line(fresh("rival"), "R", 0, "", IdentityInception)
				ri.Inception = &Inception{Profile: FixedRoot}
				ev := line(fresh("rival-ev"), "R", 1, ri.ID, Inert)
				rival = append(rival, ri.ID, ev.ID)
				add = append(add, ri, ev)
			case 2: // root fork (inert)
				add = append(add, rootLine(Inert))
			case 3: // root merge of two root lines
				f := rootLine(Inert)
				other := root[rng.Intn(len(root))]
				if other != f.Prev {
					f.Merges = []ID{other}
					f.Seq = max(seqOf[f.Prev], seqOf[other]) + 1
				}
				add = append(add, f)
			case 4: // cut placed before its grant, on a root fork (prev = I)
				c := cut(fresh("cut-before"), pick())
				c.Prev, c.Seq = "I", 1
				add = append(add, c)
			case 5: // cut with a missing prev
				c := cut(fresh("cut-missing"), pick())
				c.Prev, c.Seq = ID(fmt.Sprintf("never-held-%d", n)), 7
				add = append(add, c)
			case 6: // cut on a rival lineage
				if len(rival) == 0 {
					continue
				}
				c := cut(fresh("cut-rival"), pick())
				c.Prev, c.Seq = rival[0], 1
				add = append(add, c)
			case 7: // unsupported root line
				f := rootLine(Inert)
				f.Validity = Unsupported
				add = append(add, f)
			case 8: // invalid root line
				f := rootLine(Inert)
				f.Validity = Invalid
				add = append(add, f)
			case 9: // sibling grant to another key
				g := rootLine(GrantEvent)
				g.Grant = &Grant{Identity: "I", Delegate: "K2", Inception: "D2", Permissions: []Permission{{Kind: Authored, Mode: AnyTarget}}}
				add = append(add, line("D2", "K2", 0, "", Inert), g)
			case 10: // a second identity J granting the same K
				j := line(fresh("J"), "R2", 0, "", IdentityInception)
				j.Inception = &Inception{Profile: FixedRoot}
				g := line(fresh("GJ"), "R2", 1, j.ID, GrantEvent)
				g.Grant = &Grant{Identity: j.ID, Delegate: "K", Inception: "D", Permissions: []Permission{{Kind: Authored, Mode: AnyTarget}}}
				add = append(add, j, g)
			case 11: // delegate self-event
				prev := pick()
				add = append(add, line(fresh("k-self"), "K", 9, prev, []Event{RotateKey, RevokeKey}[rng.Intn(2)]))
			case 12: // K line with a missing link
				f := data(fresh("k-dangling"), 9, ID(fmt.Sprintf("never-held-k-%d", n)))
				add = append(add, f)
			case 13: // root event with a rejected signature
				c := cut(fresh("cut-badsig"), "")
				c.Authentication = RejectedSignature
				add = append(add, c)
			case 14: // unsupported sibling grant, or an ordinary cut
				if rng.Intn(2) == 0 {
					g := rootLine(GrantEvent)
					g.Validity = Unsupported
					g.Grant = &Grant{Identity: "I", Delegate: "K3", Inception: "D3", Permissions: []Permission{{Kind: Authored, Mode: AnyTarget}}}
					add = append(add, g)
				} else {
					c := cut(fresh("cut"), pick())
					prev := root[rng.Intn(len(root))]
					c.Prev, c.Seq = prev, seqOf[prev]+1
					add = append(add, c)
				}
			}
			for _, f := range add {
				if f.Signer == "R" && f.Authentication == Authenticated && f.Event != IdentityInception && !slices.Contains(rival, f.ID) && !strings.HasPrefix(string(f.Prev), "never-held") && !slices.Contains(rival, f.Prev) {
					root = append(root, f.ID)
					seqOf[f.ID] = f.Seq
				}
			}
			fs = append(fs, add...)
			after := snapshot(t, fs)
			for _, id := range candidates {
				was, now := before.Evaluate(id).Status, after.Evaluate(id).Status
				if rank[now] > rank[was] {
					t.Fatalf("seed %d step %d: %s rose %s → %s after adding %v", seed, step, id, was, now, ids(add))
				}
				if now != was {
					moves[string(was)+"→"+string(now)]++
				}
			}
			before = after
		}
	}
	t.Logf("status moves over 150 seeds × 8 steps: %v (none upward)", moves)
}

func ids(fs []Fact) []ID {
	var out []ID
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}
