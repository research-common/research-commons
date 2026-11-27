package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
)

// heldByScan is held as it was before the resolver indexed statements by what they are about: every describes,
// refutes, retracts and reproduced statement read for every blob. The index must answer what this answers.
func heldByScan(r *Resolver, a *Artifact) []*Placed {
	claimIDs := map[string]*Claim{}
	for _, c := range a.Claims {
		for _, id := range c.Statements {
			claimIDs[id] = c
		}
	}
	var out []*Placed
	for _, kind := range []string{"describes", "refutes", "retracts", "reproduced"} {
		for _, p := range r.byKind[kind] {
			if !p.EvidenceReady() {
				continue
			}
			b := p.St.Body
			switch kind {
			case "describes":
				ao := object(b, "about")
				if str(ao, "content") == a.Digest || claimIDs[str(ao, "statement")] != nil {
					out = append(out, p)
				}
			case "refutes", "retracts":
				if claimIDs[str(b, "of")] != nil {
					out = append(out, p)
				}
			case "reproduced":
				if c := claimIDs[str(b, "of")]; c != nil && provenance(b).key() != c.Provenance.key() {
					out = append(out, p)
				}
			}
		}
	}
	slices.SortFunc(out, func(x, y *Placed) int { return strings.Compare(x.St.Kind+x.St.ID, y.St.Kind+y.St.ID) })
	return out
}

func placedIDs(ps []*Placed) string {
	ids := make([]string, len(ps))
	for i, p := range ps {
		ids[i] = p.St.Kind + ":" + p.St.ID
	}
	return strings.Join(ids, " ")
}

// TestIndexesAnswerWhatTheScansAnswered: the resolver's two indexes are the per-kind lists split, nothing more.
// For every kind and every blob, on(kind, d) is byKind[kind] filtered by the content digest, in the same order;
// and for every blob, held (read through byLink) lists what the scan over all four kinds listed.
func TestIndexesAnswerWhatTheScansAnswered(t *testing.T) {
	w := newWorld(t)
	blobs := []string{"X0", "X1", "X2", "X3", "X4", "X5"}
	keys := []string{"Aa", "Ba", "Ca"}
	for i, x := range blobs {
		for j, k := range keys {
			if (i+j)%3 == 2 {
				continue // not every key claims every blob
			}
			name := fmt.Sprintf("%s-%s", k, x)
			if i%2 == 0 {
				w.authored(name, k, x, "prov", []string{"W" + k, "IN"})
			} else {
				w.authored(name, k, x)
			}
			w.sign("h-"+name, k, "holds", obj("content", contentOf(x)))
		}
	}
	a0, b1 := w.ids["Aa-X0"], w.ids["Aa-X1"]
	if a0 == "" || b1 == "" {
		t.Fatal("the fixture lost a claim the links name")
	}
	w.sign("d1", "Ca", "describes", obj("about", obj("content", dig("X0")), "note", "about the blob"))
	w.sign("d2", "Ba", "describes", obj("about", obj("statement", a0), "note", "about a claim"))
	w.sign("d3", "Aa", "describes", obj("about", obj("content", dig("X3")), "note", "another blob"))
	w.sign("d4", "Ca", "describes", obj("about", obj("content", dig("NOBODY")), "note", "a blob nobody claims"))
	w.sign("f1", "Ca", "refutes", obj("of", a0, "evidence", dig("E")))
	w.sign("f2", "Ca", "refutes", obj("of", b1, "evidence", dig("X2")))
	w.sign("t1", "Aa", "retracts", obj("of", b1, "reason", "wrong file"))
	w.sign("r1", "Ba", "reproduced", obj("of", a0, "result", "match", "content", contentOf("X0"),
		"provenance", obj("workflow", dig("WOther"), "inputs", []string{dig("IN")})))
	w.sign("r2", "Ca", "reproduced", obj("of", a0, "result", "match", "content", contentOf("X0"),
		"provenance", obj("workflow", dig("WAa"), "inputs", []string{dig("IN")})))
	w.sign("hw", "Aa", "holds", obj("content", contentOf("X0"), "withdrawn", true))
	// one key claiming a blob twice (the first is amended), and a second key in the same derivation group
	w.authored("Aa-X4-again", "Aa", "X4", "prov", []string{"WAa", "IN"})
	w.authored("Ba-X4-shared", "Ba", "X4", "prov", []string{"WAa", "IN"})
	// statements this reader cannot evaluate (an unknown critical extension), with bodies no schema checked: they
	// are filed like any other and must be skipped before anything in them is read
	signCritical(w, "u1", "Ca", "reproduced", obj("content", contentOf("X0"), "of", a0, "provenance", false))
	signCritical(w, "u2", "Ca", "describes", obj("about", false))
	signCritical(w, "u3", "Ca", "refutes", obj("of", a0, "evidence", canon.Array{}))
	signCritical(w, "u4", "Ca", "authored", obj("content", "not an object", "provenance", canon.Null{}))
	signCritical(w, "u5", "Ca", "holds", obj("content", contentOf("X0"), "locations", "not a list"))
	r := w.store(nil)

	digests := map[string]bool{"": true, dig("NOBODY"): true, dig("E"): true}
	for _, x := range blobs {
		digests[dig(x)] = true
	}
	filed := 0
	for kind, all := range r.byKind {
		for d := range digests {
			var want []*Placed
			for _, p := range all {
				if contentDigest(p.St.Body) == d {
					want = append(want, p)
				}
			}
			if got := r.on(kind, d); placedIDs(got) != placedIDs(want) {
				t.Fatalf("on(%s, %s):\n got %s\nwant %s", kind, d, placedIDs(got), placedIDs(want))
			}
			filed += len(want)
		}
	}
	total := 0
	for _, all := range r.byKind {
		total += len(all)
	}
	if filed != total {
		t.Fatalf("the digests asked about cover %d of %d placed statements: the comparison must reach every one", filed, total)
	}

	// byProv: the statements of a kind with one provenance, in byKind order. A statement filed nowhere (its
	// provenance is present and not an object) must be one that never counts, since no group walk sees it.
	groups, unfiled := 0, 0
	for _, kind := range []string{"authored", "reproduced"} {
		want := map[string][]*Placed{}
		for _, p := range r.byKind[kind] {
			if p.St.Body == nil {
				continue
			}
			v, has := p.St.Body.Get("provenance")
			if _, isObj := v.(*canon.Object); has && !isObj {
				if r.gate(p).Counts {
					t.Fatalf("%s %s has a provenance that is not an object and counts", kind, p.St.ID)
				}
				unfiled++
				continue
			}
			k := provenance(p.St.Body).key()
			want[k] = append(want[k], p)
		}
		if len(r.byProv[kind]) != len(want) {
			t.Fatalf("byProv[%s] has %d provenances, the scan %d", kind, len(r.byProv[kind]), len(want))
		}
		for k, ps := range want {
			if got := r.byProv[kind][k]; placedIDs(got) != placedIDs(ps) {
				t.Fatalf("byProv[%s][%s]:\n got %s\nwant %s", kind, k, placedIDs(got), placedIDs(ps))
			}
			if len(ps) > 1 && k != "" {
				groups++
			}
		}
	}
	if groups == 0 || unfiled == 0 {
		t.Fatalf("%d provenances with more than one run, %d unfiled statements: the fixture must have both", groups, unfiled)
	}
	// amended, as the scan over every authored statement answered it
	amendedSeen := 0
	for _, q := range r.byKind["authored"] {
		want := false
		d := contentDigest(q.St.Body)
		for _, o := range r.byKind["authored"] {
			want = want || o.St.Signer == q.St.Signer && r.countsAsKey(o) && contentDigest(o.St.Body) == d && r.precedes(q.St.Signer, q.St.ID, o.St.ID)
		}
		if got := r.amended(q); got != want {
			t.Fatalf("amended(%s) = %v, the scan says %v", q.St.ID, got, want)
		}
		if want {
			amendedSeen++
		}
	}
	if amendedSeen == 0 {
		t.Fatal("no amended claim in the fixture")
	}
	// the group both keys derived X4 in holds one current run per key
	if g := r.Group(&Provenance{Workflow: dig("WAa"), Inputs: []string{dig("IN")}}); len(g.Derivers) != 2 {
		t.Fatalf("the shared group has derivers %v", g.Derivers)
	}

	nonEmpty := 0
	for d := range digests {
		a := r.authorship(d)
		got, want := r.held(a), heldByScan(r, a)
		if placedIDs(got) != placedIDs(want) {
			t.Fatalf("held(%s):\n got %s\nwant %s", d, placedIDs(got), placedIDs(want))
		}
		if len(want) > 0 {
			nonEmpty++
		}
	}
	// X0 carries a describes of the blob, one of a claim, a refutes and a reproduced under another provenance;
	// X1 a refutes and a retracts; X3 and the unclaimed blob a describes each
	if got := placedIDs(r.held(r.authorship(dig("X0")))); strings.Count(got, "describes:") != 2 || strings.Count(got, "refutes:") != 1 || strings.Count(got, "reproduced:") != 1 {
		t.Fatalf("held(X0) = %s", got)
	}
	if nonEmpty < 4 {
		t.Fatalf("only %d blobs have held statements: the fixture no longer exercises the index", nonEmpty)
	}
}

// manyBlobs is a store of keys*perKey derived blobs: each has an authored (with its own provenance), a holds and
// a describes by its key.
func manyBlobs(t *testing.T, keys, perKey int) (*Resolver, []string) {
	w := newWorld(t)
	var ds []string
	for k := 0; k < keys; k++ {
		n := fmt.Sprintf("K%03da", k)
		for i := 0; i < perKey; i++ {
			x := fmt.Sprintf("blob-%d-%d", k, i)
			w.authored("a-"+x, n, x, "licence", "CC0-1.0", "prov", []string{"WF", "in-" + x})
			w.sign("h-"+x, n, "holds", obj("content", contentOf(x)))
			w.sign("d-"+x, n, "describes", obj("about", obj("content", dig(x)), "note", "n"))
			ds = append(ds, dig(x))
		}
	}
	return w.store(nil), ds
}

// TestEveryBlobCostIsLinear: asking about every blob of a store, which is what `list` does, costs about one unit
// per blob. Each question once read every authored, holds, describes, refutes, retracts and reproduced
// statement in the store (its claims, its holders, what is held about it, its derivation group, whether a claim
// was amended), so the whole cost the square of the store (#291). Two sizes are compared, so the test
// does not depend on the machine: four times the blobs must cost well under the sixteen times of a quadratic walk.
func TestEveryBlobCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("signs a few thousand statements")
	}
	const keys, small, factor = 40, 10, 4
	walk := func(r *Resolver, ds []string) time.Duration {
		best := time.Duration(0)
		for try := 0; try < 3; try++ { // the best of three: a pause on a busy machine is not a slope
			start := time.Now()
			for _, d := range ds {
				if a := r.Artifact(d); len(a.Claims) != 1 || len(a.Holders) != 1 || len(a.Held) != 1 {
					t.Fatalf("blob %s: %d claims, %d holders, %d held", d, len(a.Claims), len(a.Holders), len(a.Held))
				}
			}
			if d := time.Since(start); try == 0 || d < best {
				best = d
			}
		}
		return best
	}
	rs, ds := manyBlobs(t, keys, small)
	rl, dl := manyBlobs(t, keys, small*factor)
	dSmall, dLarge := walk(rs, ds), walk(rl, dl)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("%d blobs %s, %d blobs %s: %.1f times", len(ds), dSmall, len(dl), dLarge, ratio)
	if ratio > 2.5*factor {
		t.Fatalf("%d blobs took %s and %d blobs took %s (%.1f times): asking about every blob is not linear in the store", len(ds), dSmall, len(dl), dLarge, ratio)
	}
}

// BenchmarkEveryBlob asks about every blob of a store once: the resolver's share of `list`.
func BenchmarkEveryBlob(b *testing.B) {
	for _, perKey := range []int{10, 40} {
		r, ds := manyBlobs(&testing.T{}, 40, perKey)
		b.Run(fmt.Sprintf("blobs=%d", len(ds)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for _, d := range ds {
					_ = r.Artifact(d)
				}
			}
		})
	}
}
