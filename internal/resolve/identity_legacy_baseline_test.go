package resolve

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
)

// These are characterization snapshots of the bare-key resolver, not proposed identity
// authorization rules. Keep them unchanged when moving legacy behavior behind a new seam.
// The focused conformance/property tests remain the authority for individual rules; here
// their public synthetic constructions are sampled across the Statement, Resource and
// Artifact surfaces together, including fields/reasons not all present in Render.
// No identity, time-verifier or comparator mocks are needed: world signs real wire lines.
type identityLegacyCase struct {
	name     string
	w        *world
	held     []int // nil = all lines; an explicit subset models a reader with a gap
	resource string
	blob     string
}

func identityLegacyCases(t *testing.T) []identityLegacyCase {
	t.Helper()
	var cases []identityLegacyCase

	// TestDetachedEditionWaitsForRevocation / TestKeyEventsReachAuthorship:
	// a verified signature is not eligibility. The hard revocation applies even
	// though its own line is beyond last_good and does not itself count.
	w := newWorld(t)
	first := w.authored("A0", "A", "X", "licence", "MIT")
	w.sign("UNKNOWN", "A", "endorses", obj("content", contentOf("X")))
	w.sign("REV", "A", "revoke_key", obj("reason", "key_compromise", "last_good", first))
	w.authored("LATE", "A", "X", "licence", "CC0-1.0")
	cases = append(cases,
		identityLegacyCase{name: "placement-gap", w: w, held: []int{0, 1, 3}, blob: "X"},
		identityLegacyCase{name: "placement-revoked", w: w, blob: "X"})

	// TestRevocationReachesBackwards: a soft self-revocation on a low fork
	// doubts an earlier approval and its successor, but an approval after the
	// revocation is simply unauthorized. Verification/chaining stay intact.
	w = newWorld(t)
	g := w.genesis("G", "K", 0, "K", "M")
	head, seq := w.head["K"], w.seq["K"]
	e := w.edition("E1", "K", g, []string{g}, []string{"a"})
	w.edition("E2", "M", g, []string{e}, []string{"a", "b"})
	w.head["K"], w.seq["K"] = head, seq
	w.revoke("REV", "K", "superseded")
	w.edition("LATE", "K", g, []string{g}, []string{"late"})
	cases = append(cases, identityLegacyCase{name: "low-fork", w: w, resource: g})

	// TestKOfNSameKeyTwice, TestEditionFork, TestApprovalWithdrawal and
	// TestPredecessorByStatementID: two statements are still one controller;
	// approvals alias one edition only on Resource.Edition, never Statement.
	w = newWorld(t)
	g = w.genesis("G", "A", 2, "A", "BB", "C")
	x := w.edition("XA", "A", g, []string{g}, []string{"x"})
	w.edition("XA2", "A", g, []string{g}, []string{"x"})
	w.edition("XB", "BB", g, []string{g}, []string{"x"})
	w.edition("YA", "A", g, []string{g}, []string{"y"})
	w.edition("YB", "BB", g, []string{g}, []string{"y"})
	bad := w.editionBody(g, []string{g}, []string{"bad"})
	bad.Members["predecessors"] = canon.Array{canon.String(x)}
	w.sign("BAD", "A", "edition", bad)
	w.sign("WD", "A", "withdraw_approval", obj("resource", g, "edition", w.ed(x)))
	cases = append(cases,
		identityLegacyCase{name: "threshold-same-key", w: w, held: []int{0, 1, 2}, resource: g},
		identityLegacyCase{name: "threshold-fork", w: w, held: []int{0, 1, 2, 3, 4, 5, 6}, resource: g},
		identityLegacyCase{name: "threshold-withdrawn", w: w, resource: g})

	// TestAmendment / TestAmendmentReplacesFields: both statements still count,
	// only the descendant supplies current fields, and omitted licence is absent.
	w = newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0", "description", "readings")
	w.authored("A2", "A", "X", "description", "readings, fixed")
	w.sign("HOLDER", "BB", "holds", obj("content", contentOf("X")))
	cases = append(cases, identityLegacyCase{name: "authored-amendment", w: w, blob: "X"})
	return cases
}

func TestIdentityLegacyBaseline(t *testing.T) {
	const seed uint64 = 0x1de1717 // fixed independently of fixture size
	for _, c := range identityLegacyCases(t) {
		t.Run(c.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "identity_legacy_baseline", c.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			held := slices.Clone(c.held)
			if held == nil {
				for i := range c.w.lines {
					held = append(held, i)
				}
			}
			reverse := slices.Clone(held)
			slices.Reverse(reverse)
			orders := [][]int{held, reverse}
			for _, p := range sampleOrders(len(held), seed, 8) {
				order := make([]int, len(p))
				for i, j := range p {
					order[i] = held[j]
				}
				orders = append(orders, order)
			}
			normalize := identityLegacyNormalizer(t, c.w)
			for i, order := range orders {
				// Include interleaved duplicates and a complete replay in reverse
				// order. Each store sees duplicates, not just separately built views.
				var replay []int
				for _, j := range order {
					replay = append(replay, j, j)
				}
				for j := len(order) - 1; j >= 0; j-- {
					replay = append(replay, order[j])
				}
				for delivery, o := range [][]int{order, replay} {
					got := normalize(identityLegacySnapshot(c, c.w.store(o)))
					if got != string(want) {
						t.Fatalf("seed=%#x order=%d replay=%t delivery=%v\n--- got ---\n%s--- want ---\n%s", seed, i, delivery == 1, o, got, want)
					}
				}
			}
		})
	}
}

// Replace only fixture identifiers (full and display forms), not statuses, booleans,
// values or reason text. Longest-first replacement prevents a shortened ID from
// masking a full ID. Collisions fail rather than silently hiding distinct identities.
// Editions use the alphabetically first approval label, so aliases stay visible.
func identityLegacyNormalizer(t *testing.T, w *world) func(string) string {
	t.Helper()
	names := map[string]string{}
	add := func(id, name string) {
		if old, ok := names[id]; ok && old != name {
			t.Fatalf("normalization collision for %q: %s / %s", id, old, name)
		}
		names[id] = name
	}
	editions := map[string]bool{}
	for _, name := range sortedKeys(w.ids) {
		id := w.ids[name]
		add(id, "st:"+name)
		add(keylog.Short(id), "st:"+name)
		if eid, ok := w.eid[id]; ok && !editions[eid] {
			add(eid, "ed:"+name)
			add(keylog.Short(eid), "ed:"+name)
			editions[eid] = true
		}
	}
	for _, name := range sortedKeys(w.keys) {
		key := w.signer(name)
		add(key, "key:"+name)
		add(shortKey(key), "key:"+name)
	}
	keys := sortedKeys(names)
	slices.SortStableFunc(keys, func(a, b string) int { return len(b) - len(a) })
	var pairs []string
	for _, k := range keys {
		pairs = append(pairs, k, names[k])
	}
	return strings.NewReplacer(pairs...).Replace
}

// The snapshot is deliberately a small semantic projection, not a second resolver
// or a serialization of private caches. Preserve returned slice/reason order; sort
// only maps and fixture query names. A change to these selected outputs must fail
// against a checked-in expectation even if every delivery order changes identically.
func identityLegacySnapshot(c identityLegacyCase, r *Resolver) string {
	var b strings.Builder
	for _, name := range sortedKeys(c.w.ids) {
		id := c.w.ids[name]
		p, ok := r.Statement(id)
		if !ok {
			fmt.Fprintf(&b, "statement %s missing\n", id)
			continue
		}
		fmt.Fprintf(&b, "statement %s -> %s signer=%s kind=%s alg=%s status=%q verified=%t chained=%t evaluable=%t counts=%t\n",
			id, p.St.ID, p.St.Signer, p.St.Kind, p.St.Alg, p.St.Status, p.St.Verified, p.Chained, p.Evaluable, p.Counts())
		fmt.Fprintf(&b, "  wire-why=%q after=%q doubted=%q\n", p.St.Why, p.After, p.Doubted)
	}
	if c.resource != "" {
		res, ok := r.Resource(c.resource)
		if !ok {
			fmt.Fprintf(&b, "resource %s missing\n", c.resource)
		} else {
			fmt.Fprintf(&b, "resource %s current=%q tips=%q contested=%q no-controller=%t verify=%d\n",
				res.ID, res.Current, res.Tips, res.Contested, res.NoController, res.VerifyExit())
			for _, k := range sortedKeys(res.RevokedControllers) {
				fmt.Fprintf(&b, "  retired %s by %s\n", k, res.RevokedControllers[k])
			}
			for _, e := range res.Editions {
				fmt.Fprintf(&b, "  edition %s state=%s predecessors=%q controllers=%q k=%d\n", e.ID, e.State, e.Predecessors, e.Controllers, e.K)
				for _, a := range e.Approvals {
					fmt.Fprintf(&b, "    approval %s signer=%s counted=%t doubted=%t withdrawn=%q why=%q\n",
						a.Statement, a.Signer, a.Counted, a.Doubted, a.Withdrawn, a.Why)
				}
				fmt.Fprintf(&b, "    explain=%q\n", e.Explain)
				identityLegacyLookup(&b, r, res, e.ID)
				for _, a := range e.Approvals {
					identityLegacyLookup(&b, r, res, a.Statement)
				}
			}
			for _, f := range res.Forks {
				fmt.Fprintf(&b, "  fork %+v cleared=%t\n", f, f.Cleared())
			}
			identityLegacyLookup(&b, r, res, res.ID)
			identityLegacyLookup(&b, r, res, strings.Repeat("0", 64))
		}
	}
	if c.blob != "" {
		a := r.Artifact(dig(c.blob))
		exit, why := a.VerifyExit()
		fmt.Fprintf(&b, "artifact %s state=%q verify=%d why=%q explain=%q holders=%q\n", c.blob, a.State, exit, why, a.Explain, a.Holders)
		for _, claim := range a.Claims {
			fmt.Fprintf(&b, "  claim signer=%s statements=%q current=%q\n", claim.Signer, claim.Statements, claim.Current)
			for _, id := range sortedKeys(claim.Amends) {
				fmt.Fprintf(&b, "    %s amends=%q\n", id, claim.Amends[id])
			}
		}
		for _, p := range a.NotCounted {
			fmt.Fprintf(&b, "  not-counted %s signer=%s why=%q\n", p.Statement, p.Signer, p.Why)
		}
		for _, name := range []string{"description", "licence", "type"} {
			f := a.Field(name)
			value, ok := f.Default()
			fmt.Fprintf(&b, "  field %s state=%q default=%q present=%t from=%+v rivals=%+v\n", name, f.State, value, ok, f.From, f.Rivals)
		}
	}
	return b.String()
}

func identityLegacyLookup(b *strings.Builder, r *Resolver, res *Resource, id string) {
	statement, edition := "missing", "missing"
	if p, ok := r.Statement(id); ok {
		statement = p.St.ID
	}
	if e, ok := res.Edition(id); ok {
		edition = e.ID
	}
	fmt.Fprintf(b, "  lookup %s statement=%s edition=%s\n", id, statement, edition)
}
