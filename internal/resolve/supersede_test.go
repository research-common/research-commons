package resolve

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// refusingBitcoin is fakeBitcoin that also refuses proofs named "refused:…" (an operational refusal under the
// bitcoin-time note §4: no bound, the anchor named).
type refusingBitcoin struct {
	fakeBitcoin
	refused map[string]bool
}

func newRefusingBitcoin(refused []string, heights ...int64) refusingBitcoin {
	f := refusingBitcoin{fakeBitcoin: newFakeBitcoin(heights...), refused: map[string]bool{}}
	for _, n := range refused {
		f.refused[dig(n)] = true
	}
	return f
}

func (f refusingBitcoin) Verify(a *wire.Statement) Bound {
	if f.refused[str(a.Body, "proof")] {
		return Bound{Quality: NoBound, Anchor: a.ID, Why: "refused: proof exceeds the reader's limit", State: "refused"}
	}
	return f.fakeBitcoin.Verify(a)
}

// anchorOf signs an `anchors` by key n covering head (not necessarily n's current head) with the named proof.
func (w *world) anchorOf(name, n, head, proof string) string {
	return w.sign(name, n, "anchors", obj("covered", head, "proof", dig(proof), "proof_format", "ots-detached-v1"))
}

// pair is a world in which A authors X (head h) and signs two anchors lines a1 then a2 for h, a2 after a1 in log
// order.
type pair struct {
	w         *world
	h, a1, a2 string
}

// withIDOrder builds worlds with build(nonce) until the later line's id compares to the earlier's as
// wantLaterLower asks, so a test covers both the case where the lower-id rule and the log-order rule agree and the
// case where they disagree. build signs the head and the two lines, varying a proof name with the nonce.
func withIDOrder(t *testing.T, wantLaterLower bool, build func(nonce int) pair) pair {
	t.Helper()
	for i := 0; i < 64; i++ {
		p := build(i)
		if (p.a2 < p.a1) == wantLaterLower {
			return p
		}
	}
	t.Fatal("no nonce gave the wanted id order")
	return pair{}
}

// twoLines is a build for withIDOrder: A authors X (extra authored kv), then anchors lines with proofs p1, p2 (a
// "%d" in either takes the nonce).
func twoLines(t *testing.T, p1, p2 string, kv ...any) func(int) pair {
	return func(n int) pair {
		w := newWorld(t)
		h := w.authored("A1", "A", "X", kv...)
		name := func(p string) string {
			if strings.Contains(p, "%d") {
				return fmt.Sprintf(p, n)
			}
			return p
		}
		a1 := w.anchorOf("AA1", "A", h, name(p1))
		a2 := w.anchorOf("AA2", "A", h, name(p2))
		return pair{w, h, a1, a2}
	}
}

func displayed(t *testing.T, r *Resolver, id string) (AnchorLine, []AnchorLine) {
	t.Helper()
	ls := r.AnchorLines(id)
	var shown []AnchorLine
	for _, l := range ls {
		if l.Displayed {
			shown = append(shown, l)
		}
	}
	if len(shown) != 1 {
		t.Fatalf("displayed lines %+v of %+v", shown, ls)
	}
	return shown[0], ls
}

func lineOf(t *testing.T, ls []AnchorLine, id string) AnchorLine {
	t.Helper()
	for _, l := range ls {
		if l.Anchor == id {
			return l
		}
	}
	t.Fatalf("anchor %s not listed in %+v", keylog.Short(id), ls)
	return AnchorLine{}
}

// TestSupersessionLaterPendingDisplayed: bitcoin-time note §1 rule 5. Two pending (local) anchors of one head in
// log order: the later one is displayed, whichever id is lower, under every delivery order; explain lists both,
// the earlier one "superseded by" the later. The claim's bound names the later anchor. Priority is unchanged:
// two unverified lines still rank nothing against a verified rival.
func TestSupersessionLaterPendingDisplayed(t *testing.T) {
	conformance.Covers(t, "C-btc-31")
	for _, newerLower := range []bool{true, false} {
		pp := withIDOrder(t, newerLower, twoLines(t, "local:pending-1#%d", "local:pending-2"))
		w, h, a1, a2 := pp.w, pp.h, pp.a1, pp.a2
		for _, order := range [][]int{nil, {2, 1, 0}, {1, 0, 2}} {
			r := w.store(order)
			if b := r.bound(mustStatement(t, r, h)); b.Anchor != a2 || b.Quality != Local {
				t.Fatalf("newer id lower=%v order %v: bound %+v, want the later anchor %s (not %s)", newerLower, order, b, keylog.Short(a2), keylog.Short(a1))
			}
			shown, ls := displayed(t, r, h)
			if shown.Anchor != a2 || shown.Why != "latest in log order" || len(ls) != 2 {
				t.Fatalf("anchor lines %+v", ls)
			}
			if l := lineOf(t, ls, a1); l.Why != "superseded by "+keylog.Short(a2) {
				t.Fatalf("older line: %+v", l)
			}
			if ls[0].Anchor != a1 {
				t.Fatalf("lines not in log order: %+v", ls)
			}
			a := r.Artifact(dig("X"))
			if a.Default == nil || a.Default.Bound.Anchor != a2 {
				t.Fatalf("claimant bound: %+v", a.Default)
			}
			has(t, a.Render(), "anchor "+keylog.Short(a2))
		}
	}
}

// TestSupersessionForkedLowerID: two anchors lines of one head on forked branches of the signer's log: neither
// descends from the other, so the lower id is displayed, and explain says why.
func TestSupersessionForkedLowerID(t *testing.T) {
	conformance.Covers(t, "C-btc-31")
	w := newWorld(t)
	h := w.authored("A1", "A", "X")
	seq := w.seq["A"]
	a1 := w.anchorOf("AA1", "A", h, "local:left")
	w.forkAt("A", h, seq)
	a2 := w.anchorOf("AA2", "A", h, "local:right")
	lo, hi := min(a1, a2), max(a1, a2)
	for _, order := range [][]int{nil, {2, 1, 0}} {
		r := w.store(order)
		if b := r.bound(mustStatement(t, r, h)); b.Anchor != lo {
			t.Fatalf("forked: bound %+v, want lower id %s", b, keylog.Short(lo))
		}
		shown, ls := displayed(t, r, h)
		if shown.Anchor != lo || !strings.Contains(shown.Why, "forked branches descend from neither, so the lower id is shown") {
			t.Fatalf("forked: %+v", ls)
		}
		if l := lineOf(t, ls, hi); l.Why != "on a forked branch; "+keylog.Short(lo)+" (lower id) is shown" {
			t.Fatalf("forked, higher id: %+v", l)
		}
	}
}

// TestSupersessionVerifiedPreferred: an older verified anchor and a newer pending one for one head: the verified
// one is displayed and used, whichever id is lower; explain marks the newer one "verified preferred". The
// priority answer is the verified one's: A (verified at 100 through its older line) ranks before B (101).
func TestSupersessionVerifiedPreferred(t *testing.T) {
	conformance.Covers(t, "C-btc-31")
	for _, newerLower := range []bool{true, false} {
		pp := withIDOrder(t, newerLower, twoLines(t, "btc:100", "local:pending#%d", "licence", "CC0-1.0"))
		w, h, a1, a2 := pp.w, pp.h, pp.a1, pp.a2
		w.authored("B1", "BB", "X", "licence", "MIT")
		w.anchor("BA", "BB", "btc:101")
		opt := WithTimeVerifier(newFakeBitcoin(100, 101))
		r := w.store(nil, opt)
		if b := r.bound(mustStatement(t, r, h)); b.Anchor != a1 || !b.verified() || b.Height != 100 {
			t.Fatalf("bound %+v, want the verified older anchor", b)
		}
		shown, ls := displayed(t, r, h)
		if shown.Anchor != a1 || shown.Why != "verified preferred (the earliest verified bound for this head)" {
			t.Fatalf("lines %+v", ls)
		}
		if l := lineOf(t, ls, a2); l.Why != "verified preferred ("+keylog.Short(a1)+")" {
			t.Fatalf("newer pending line: %+v", l)
		}
		everyOrderArtifact(t, w, "X", func(a *Artifact) {
			wantAuthorship(t, a, Priority)
			wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
			has(t, a.Render(), "earlier-commitment")
			has(t, a.Render(), "bitcoin mainnet height 100 (anchor "+keylog.Short(a1)+")")
		}, opt)
	}
}

// TestSupersessionRefusedNeverDisplaces: a newer refused anchors line beside an older pending one: the pending
// one is still the displayed bound (a refused anchor never displaces a usable one). With only refused lines, the
// latest refused line is shown as refused, and still no bound.
func TestSupersessionRefusedNeverDisplaces(t *testing.T) {
	conformance.Covers(t, "C-btc-31")
	for _, newerLower := range []bool{true, false} {
		pp := withIDOrder(t, newerLower, twoLines(t, "local:pending#%d", "refused:big"))
		w, h, a1, a2 := pp.w, pp.h, pp.a1, pp.a2
		r := w.store(nil, WithTimeVerifier(newRefusingBitcoin([]string{"refused:big"})))
		if b := r.bound(mustStatement(t, r, h)); b.Anchor != a1 || b.Quality != Local {
			t.Fatalf("bound %+v, want the older pending anchor", b)
		}
		shown, ls := displayed(t, r, h)
		if shown.Anchor != a1 {
			t.Fatalf("lines %+v", ls)
		}
		if l := lineOf(t, ls, a2); l.Why != "refused; a refused anchor never displaces a usable one ("+keylog.Short(a1)+")" {
			t.Fatalf("refused line: %+v", l)
		}
	}
	// only refused lines: the latest in log order is shown, as refused
	pp := withIDOrder(t, true, twoLines(t, "refused:a", "refused:b#%d"))
	var refused []string
	for i := 0; i < 64; i++ {
		refused = append(refused, fmt.Sprintf("refused:b#%d", i))
	}
	w, h, a2 := pp.w, pp.h, pp.a2
	r := w.store(nil, WithTimeVerifier(newRefusingBitcoin(append(refused, "refused:a"))))
	b := r.bound(mustStatement(t, r, h))
	if b.Quality != NoBound || b.Anchor != a2 || !strings.Contains(b.String(), "refused") {
		t.Fatalf("all refused: bound %+v", b)
	}
	if shown, _ := displayed(t, r, h); !strings.Contains(shown.Why, "every anchors line for this head is refused") {
		t.Fatalf("all refused: %+v", shown)
	}
}

// TestSupersessionSingleAnchorUnchanged: one anchors line is displayed as the only one, and the bound is what it
// always was.
func TestSupersessionSingleAnchorUnchanged(t *testing.T) {
	w := newWorld(t)
	h := w.authored("A1", "A", "X")
	a := w.anchor("AA", "A", "local:only")
	r := w.store(nil)
	if b := r.bound(mustStatement(t, r, h)); b.Anchor != a || b.Quality != Local {
		t.Fatalf("bound %+v", b)
	}
	if shown, ls := displayed(t, r, h); shown.Why != "the only anchors line for this head" || len(ls) != 1 {
		t.Fatalf("lines %+v", ls)
	}
}

func mustStatement(t *testing.T, r *Resolver, id string) *wire.Statement {
	t.Helper()
	p, ok := r.Statement(id)
	if !ok {
		t.Fatalf("statement %s not held", keylog.Short(id))
	}
	return p.St
}
