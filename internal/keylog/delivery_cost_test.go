package keylog

import (
	"fmt"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// chainedFixedPoint is the definition View's one pass must reach: iterate "prev chained (or seq 0) and every
// merges entry chained" over the lines that are not refused until nothing changes.
func chainedFixedPoint(l *Log) map[string]bool {
	nodes := l.nodes()
	refused := map[string]bool{}
	for _, st := range nodes {
		if l.relativeRule(st, nodes) != nil {
			refused[st.ID] = true
		}
	}
	chained := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for id, st := range nodes {
			if chained[id] || refused[id] {
				continue
			}
			ok := st.Seq == 0 || chained[st.Prev]
			for _, m := range st.Merges {
				ok = ok && chained[m]
			}
			if ok {
				chained[id], changed = true, true
			}
		}
	}
	return chained
}

// genMixedLog is genLog with unknown-alg lines mixed in (vouched when a later verified line follows them) and,
// now and then, a line whose seq does not follow its prev, so retained lines and log-relative refusals occur.
func genMixedLog(k wire.Key, seed uint64) []line {
	x := seed*0x9e3779b97f4a7c15 + 7
	rnd := func(n int) int { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return int(x % uint64(n)) }
	all := []line{mk(k, 0, "", 0, "")}
	seqOf := map[string]int64{all[0].id: 0}
	n := 3 + rnd(10)
	for i := 1; i < n; i++ {
		p := all[rnd(len(all))]
		seq := seqOf[p.id] + 1
		var l line
		switch rnd(8) {
		case 0:
			l = unknownAlg(k, seq, p.id, byte(i))
		case 1:
			seq += 2 // seq is not prev's plus 1: refused by the log-relative rule once prev is held
			l = mk(k, seq, p.id, byte(i), "")
		default:
			var merges []string
			if rnd(3) == 0 {
				if m := all[rnd(len(all))]; m.id != p.id {
					merges = []string{m.id}
				}
			}
			l = mk(k, seq, p.id, byte(i), "", merges...)
		}
		seqOf[l.id] = seq
		all = append(all, l)
	}
	var out []line
	for _, l := range all {
		if rnd(7) != 0 {
			out = append(out, l)
		}
	}
	return out
}

// TestAddAgreesWithView: the refusal Add returns for a line is the one the log's View gives that line at that
// moment, for every line of every delivery order tried, over generated logs with forks, merges, gaps, unknown-alg
// lines and broken seqs. And the chained set View computes in one pass is the fixed point of its definition.
func TestAddAgreesWithView(t *testing.T) {
	k := key("A")
	refusals, retained, detached := 0, 0, 0
	for seed := uint64(1); seed <= 300; seed++ {
		ls := genLog(k, seed)
		if seed%2 == 0 {
			ls = genMixedLog(k, seed)
		}
		for p := uint64(0); p < 6; p++ {
			s := NewStore()
			l := s.Log(k.Signer())
			for _, i := range shuffle(len(ls), seed*977+p) {
				st, err := l.Add(ls[i].bytes)
				if st == nil {
					t.Fatalf("seed %d: a generated line was not read: %v", seed, err)
				}
				v := l.View()
				want := v.refusalOf(st.ID)
				got, _ := err.(*refusal.Refusal)
				if !st.Verified {
					want = nil // an unverified line is retained; Add reports nothing for it
				}
				if (got == nil) != (want == nil) || (got != nil && (got.Reason != want.Reason || got.Detail != want.Detail)) {
					t.Fatalf("seed %d order %d line %s: Add says %v, View says %v\n%s", seed, p, Short(st.ID), got, want, v.Render())
				}
				if got != nil {
					refusals++
				}
				fp := chainedFixedPoint(l)
				for _, ln := range v.Lines {
					if (ln.State == Chained) != fp[ln.St.ID] {
						t.Fatalf("seed %d order %d: line %s is %s, the fixed point says chained=%v\n%s", seed, p, Short(ln.St.ID), ln.State, fp[ln.St.ID], v.Render())
					}
					if ln.State == Detached {
						detached++
					}
				}
				retained += len(v.Retained)
			}
		}
	}
	// the generator must actually reach the cases the comparison is for
	if refusals == 0 || retained == 0 || detached == 0 {
		t.Fatalf("generated logs reached %d refusals, %d retained lines, %d detached lines: each must occur", refusals, retained, detached)
	}
}

// TestLongLogDelivery: delivering one key's long log costs about one unit per line. Delivery once built the
// whole View for every line added, so the cost of every command that reads a store grew with the square of the
// longest log (4,000 lines: tens of seconds). The test compares two sizes rather than a wall-clock bound, so it
// does not depend on the machine: four times the lines must cost well under the sixteen times a quadratic
// delivery costs.
func TestLongLogDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("signs and delivers 5,000 lines")
	}
	const small, factor = 1000, 4
	k := key("A")
	ls := longChain(k, small*factor)
	deliverAll := func(n int) (time.Duration, View) {
		best := time.Duration(0)
		var v View
		// The best of three: a pause on a busy machine is not a slope. The stored reader verifies a given line
		// once per process, so the later tries time the delivery itself, without the signature checks.
		for try := 0; try < 3; try++ {
			start := time.Now()
			s := NewStoredStore()
			l := s.Log(k.Signer())
			for _, x := range ls[:n] {
				if _, err := l.Add(x.bytes); err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
			}
			v = l.View()
			if d := time.Since(start); try == 0 || d < best {
				best = d
			}
		}
		return best, v
	}
	dSmall, _ := deliverAll(small)
	dLarge, v := deliverAll(small * factor)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("%d lines %s, %d lines %s: %.1f times", small, dSmall, small*factor, dLarge, ratio)
	if ratio > 2.5*factor {
		t.Fatalf("%d lines took %s and %d lines took %s (%.1f times): delivery is not linear in the log", small, dSmall, small*factor, dLarge, ratio)
	}
	n := small * factor
	if len(v.Lines) != n || len(v.Tips) != 1 || v.Tips[0] != ls[n-1].id || len(v.Refused) != 0 || len(v.Forks) != 0 {
		t.Fatalf("%d lines, tips %v, %d refused, %d forks", len(v.Lines), shorts(v.Tips), len(v.Refused), len(v.Forks))
	}
	for _, ln := range v.Lines {
		if ln.State != Chained {
			t.Fatalf("line at seq %d is %s", ln.St.Seq, ln.State)
		}
	}
}

// longChain is chain for logs longer than its one-byte tag allows: line i holds a digest made from i.
func longChain(k wire.Key, n int) []line {
	out := make([]line, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		b, id := wire.Sign(wire.Draft{Kind: "holds", Seq: int64(i), Prev: prev,
			TS: fmt.Sprintf("2026-10-%02dT%02d:%02d:%02dZ", 1+(i/86400)%28, (i/3600)%24, (i/60)%60, i%60), Body: holdsN(i)}, k)
		out = append(out, line{b, id})
		prev = id
	}
	return out
}

// holdsN is a holds body whose digest is made from i.
func holdsN(i int) *canon.Object {
	d := canon.String("sha256:" + fmt.Sprintf("%064x", i))
	return &canon.Object{Keys: []string{"content"}, Members: map[string]canon.Value{
		"content": &canon.Object{Keys: []string{"digest", "size"}, Members: map[string]canon.Value{"digest": d, "size": canon.Int(1)}}}}
}

// BenchmarkLogDelivery delivers one key's log of n lines and takes its View once: what every command that reads
// a store does for every key. Linear in n.
func BenchmarkLogDelivery(b *testing.B) {
	k := key("A")
	for _, n := range []int{250, 1000, 4000} {
		ls := longChain(k, n)
		b.Run(fmt.Sprintf("lines=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				s := NewStoredStore()
				l := s.Log(k.Signer())
				for _, x := range ls {
					_, _ = l.Add(x.bytes)
				}
				_ = l.View()
			}
		})
	}
}
