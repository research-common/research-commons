package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// beforeEverything is earlier than any ts sign produces, so a line signed with it after another is incoherent.
const beforeEverything = "2026-10-16T00:00:00Z"

// coherentTS is a ts later than every ts sign produces for a short log.
const coherentTS = "2026-10-16T03:00:00Z"

// placedIncoherent reports the resolver's flag for statement id (and fails if the statement is not held).
func placedIncoherent(t *testing.T, r *Resolver, id string) bool {
	t.Helper()
	p, ok := r.Statement(id)
	if !ok {
		t.Fatalf("statement %s not held", keylog.Short(id))
	}
	if !p.St.Verified || p.St.Status != wire.Valid {
		t.Fatalf("statement %s: verified %v, status %s: the signature is reported valid whatever the flag", keylog.Short(id), p.St.Verified, p.St.Status)
	}
	return p.Incoherent
}

// TestIncoherentLineNoBound: C-core-106 at the resolver. Key A signs a holds L1 and then an authored claim L2 on
// blob X that chains after L1 but carries an earlier ts; A anchors (verified at height 100). Rival B claims X
// with an anchor verified at height 101. L2 is flagged incoherent, its signature is still valid, and:
//   - priority: L2 has no bound, so A is not the earliest verified claimant: B (101) takes priority, A is a
//     later claimant (the control, L2 coherent, gives A priority at 100);
//   - "existed by T": the capture of an observation on an incoherent line shows no anchor, never the verified
//     height (the control shows the height);
//   - a deadline (bounds): an incoherent statement has no bound to meet it;
//   - the display: A's bound reads "no bound (incoherent line: ...)", never the height.
//
// Every delivery order gives one answer.
func TestIncoherentLineNoBound(t *testing.T) {
	conformance.Covers(t, "C-core-106")
	for _, incoherent := range []bool{true, false} {
		ts := coherentTS
		if incoherent {
			ts = beforeEverything
		}
		w := newWorld(t)
		w.sign("L1", "A", "holds", obj("content", canon.Value(contentOf("other"))))
		l2 := w.signTS("L2", "A", "authored", ts, obj("content", canon.Value(contentOf("X")), "type", "dataset", "licence", "CC0-1.0"))
		w.signTS("AA", "A", "anchors", "2026-10-16T04:00:00Z", obj("covered", w.head["A"], "proof", dig("btc:100"), "proof_format", "ots-detached-v1"))
		w.authored("B1", "BB", "X", "licence", "MIT")
		w.anchor("BA", "BB", "btc:101")
		opt := WithTimeVerifier(newFakeBitcoin(100, 101))

		r := w.store(nil, opt)
		if got := placedIncoherent(t, r, l2); got != incoherent {
			t.Fatalf("incoherent=%v: L2 flagged %v", incoherent, got)
		}
		if b := r.bound(r.byID[l2].St); incoherent != (b.Quality == NoBound) {
			t.Fatalf("incoherent=%v: L2 bound %s", incoherent, b)
		}
		if bs := r.bounds(r.byID[l2].St); incoherent != (len(bs) == 0) {
			t.Fatalf("incoherent=%v: L2 bounds %v", incoherent, bs)
		}
		sampledOrderArtifact(t, w, "X", func(a *Artifact) {
			wantAuthorship(t, a, Priority)
			out := a.Render()
			if incoherent {
				wantField(t, a, "licence", FieldDefault, `"MIT"`)
				has(t, out, "default author "+shortKey(w.signer("BB"))+",")
				has(t, out, "bitcoin mainnet height 101")
				has(t, out, "no bound ("+IncoherentWhy+")")
				hasNot(t, out, "height 100")
			} else {
				wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
				has(t, out, "default author "+shortKey(w.signer("A"))+",")
				has(t, out, "bitcoin mainnet height 100")
			}
		}, opt)
	}
}

// TestIncoherentObservationExistedBy: C-core-106, the "existed by T" use. An observation anchored at capture on
// an incoherent line shows no bound (anchored at capture, no anchor held); coherent, it shows the verified height.
func TestIncoherentObservationExistedBy(t *testing.T) {
	conformance.Partial(t, "C-core-106", "the capture display only; TestIncoherentLineNoBound covers the case")
	for _, incoherent := range []bool{true, false} {
		ts := coherentTS
		if incoherent {
			ts = beforeEverything
		}
		w := newWorld(t)
		w.sign("L1", "O1", "holds", obj("content", canon.Value(contentOf("other"))))
		o := w.signTS("O", "O1", "observed", ts, obj("content", canon.Value(contentOf("X")), "class", "none-yet", "referent", canon.Value(obj()),
			"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "anchored-at-capture"))))
		w.signTS("AA", "O1", "anchors", "2026-10-16T04:00:00Z", obj("covered", w.head["O1"], "proof", dig("btc:812000"), "proof_format", "ots-detached-v1"))
		v := obsView(t, w, o, WithTimeVerifier(newFakeBitcoin(812000)))
		out := v.Render()
		if incoherent {
			has(t, out, "evidence anchored at capture (no anchor held)")
			hasNot(t, out, "812000")
			if v.Capture.Verified == "anchored-at-capture" {
				t.Fatal("an incoherent observation's capture was verified by its anchor")
			}
		} else {
			has(t, out, "evidence anchored at capture (bitcoin mainnet height 812000")
		}
	}
}

// TestIncoherentAnchorKeepsOnlyProofBound: an `anchors` statement on an incoherent line (timestamped earlier than
// its head, bitcoin-time note §1 rule 6) keeps the bound its proof places, because the chain position comes from the
// header, and loses the local bound that rests on its own timestamp; the anchor itself is still a valid, displayed
// statement. Control: the same anchor coherent bounds them either way.
func TestIncoherentAnchorKeepsOnlyProofBound(t *testing.T) {
	conformance.Covers(t, "C-core-106")
	for _, c := range []struct {
		name       string
		anchorTS   string
		proof      string
		opts       []Option
		wantHeight bool // the covered statement's bound is the verified height
		wantLocal  bool // the covered statement's bound is local
	}{
		{"coherent, verified", "2026-10-16T04:00:00Z", "btc:100", nil, true, false},
		{"coherent, local", "2026-10-16T04:00:00Z", "local", nil, false, true},
		{"incoherent, verified", beforeEverything, "btc:100", nil, true, false},
		{"incoherent, local", beforeEverything, "local", nil, false, false},
	} {
		w := newWorld(t)
		x := w.authored("A1", "A", "X", "licence", "CC0-1.0")
		aa := w.signTS("AA", "A", "anchors", c.anchorTS, obj("covered", w.head["A"], "proof", dig(c.proof), "proof_format", "ots-detached-v1"))
		r := w.store(nil, append([]Option{WithTimeVerifier(newFakeBitcoin(100))}, c.opts...)...)
		if got := placedIncoherent(t, r, aa); got != (c.anchorTS == beforeEverything) {
			t.Fatalf("%s: anchor flagged %v", c.name, got)
		}
		if placedIncoherent(t, r, x) {
			t.Fatalf("%s: the covered statement was flagged", c.name)
		}
		b := r.bound(r.byID[x].St)
		switch {
		case c.wantHeight && (!b.verified() || b.Height != 100):
			t.Fatalf("%s: bound %s, want height 100", c.name, b)
		case c.wantLocal && b.Quality != Local:
			t.Fatalf("%s: bound %s, want local", c.name, b)
		case !c.wantHeight && !c.wantLocal && (b.Quality != NoBound || b.Anchor != ""):
			t.Fatalf("%s: bound %s, want none", c.name, b)
		}
		if n := len(r.bounds(r.byID[x].St)); n != map[bool]int{true: 1, false: 0}[c.wantHeight || c.wantLocal] {
			t.Fatalf("%s: %d bounds", c.name, n)
		}
	}
}

// TestIncoherentFlagMutation: the boundary under test is the keylog flag reaching the resolver. A resolver whose
// Placed lost the flag (the mutation) gives L2 its anchor's height back, so the test above would fail without the
// gate; this pins that the flag, not some other difference between the worlds, is what removes the bound.
func TestIncoherentFlagMutation(t *testing.T) {
	w := newWorld(t)
	w.sign("L1", "A", "holds", obj("content", canon.Value(contentOf("other"))))
	l2 := w.signTS("L2", "A", "authored", beforeEverything, obj("content", canon.Value(contentOf("X")), "type", "dataset"))
	w.signTS("AA", "A", "anchors", "2026-10-16T04:00:00Z", obj("covered", w.head["A"], "proof", dig("btc:100"), "proof_format", "ots-detached-v1"))
	r := w.store(nil, WithTimeVerifier(newFakeBitcoin(100)))
	if b := r.bound(r.byID[l2].St); b.Quality != NoBound || !strings.Contains(b.String(), "incoherent") {
		t.Fatalf("flagged: bound %s", b)
	}
	for _, p := range r.byID {
		p.Incoherent = false // mutation: the flag does not reach the resolver
	}
	if b := r.bound(r.byID[l2].St); !b.verified() || b.Height != 100 {
		t.Fatalf("mutation did not reach the boundary: bound %s", b)
	}
	if len(r.bounds(r.byID[l2].St)) != 1 {
		t.Fatal("mutation did not reach bounds")
	}
}
