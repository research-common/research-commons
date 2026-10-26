package btctime

import (
	goparser "go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
)

// TestPriorityEndToEnd: C-btc-01 and C-btc-02 with real proofs: the resolver ranks rival authored claims on bounds
// this reader verified by walking OTS proofs to headers it validated. (a) A at n, B at n+1; (b) A verified, B
// unanchored; (c) A verified, B pending; both in one block → contested, exit 3, no default field. Permuted.
func TestPriorityEndToEnd(t *testing.T) {
	conformance.Covers(t, "C-btc-01", "C-btc-02")
	for _, c := range []struct {
		name     string
		build    func(w *world)
		priority bool
		relation string
	}{
		{"n vs n+1", func(w *world) {
			w.anchorAt("AA", "A", 10)
			w.authored("B1", "BB", "X", "licence", "MIT")
			w.anchorAt("BA", "BB", 11)
		}, true, "earlier-commitment"},
		{"verified vs unanchored", func(w *world) { w.anchorAt("AA", "A", 10); w.authored("B1", "BB", "X", "licence", "MIT") }, true, "earliest verified claim"},
		{"verified vs pending", func(w *world) {
			w.anchorAt("AA", "A", 10)
			w.authored("B1", "BB", "X", "licence", "MIT")
			w.anchorProof("BA", "BB", otsFile(unhex(t, w.head["BB"]), attPending("https://bob.btc.calendar.opentimestamps.org")), ProofFormat)
		}, true, "earliest verified claim"},
		{"same block", func(w *world) {
			w.authored("B1", "BB", "X", "licence", "MIT")
			w.sameBlock(10, "AA", "A", "BA", "BB")
		}, false, "same-block"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.authored("A1", "A", "X", "licence", "CC0-1.0")
			c.build(w)
			v := w.chain(30).fresh(w.blobs)
			everyOrder(t, w, "X", v, func(a *resolveArtifact) {
				out := a.Render()
				has(t, out, c.relation)
				if !c.priority {
					if a.State != resolve.ContestedAuthorship || exitOf(a) != 3 || len(a.Units) != 2 {
						t.Fatalf("%s", out)
					}
					if f := a.Field("licence"); f.State != resolve.FieldNoDefault {
						t.Fatalf("licence %s", f.State)
					}
					return
				}
				if a.State != resolve.Priority || a.Default.Claims[0].Signer != w.signer("A") || exitOf(a) != 0 {
					t.Fatalf("%s", out)
				}
				if v, _ := a.Field("licence").Default(); v != `"CC0-1.0"` {
					t.Fatalf("licence %s", v)
				}
				has(t, out, "later claimant "+shortKey(w.signer("BB")))
				has(t, out, "verified by this reader")
				hasNot(t, out, "contested")
			})
		})
	}
}

// TestEarliestVerifiedBesideUnverified: C-btc-29. The rival is displayed as a later claimant; nothing says it could
// not have published earlier, and nothing calls it "proven later".
func TestEarliestVerifiedBesideUnverified(t *testing.T) {
	conformance.Covers(t, "C-btc-29")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X")
	w.anchorProof("BA", "BB", otsFile(unhex(t, w.head["BB"]), attPending("https://bob.btc.calendar.opentimestamps.org")), ProofFormat)
	v := w.chain(30).fresh(w.blobs)
	everyOrder(t, w, "X", v, func(a *resolveArtifact) {
		out := a.Render()
		has(t, out, "later claimant "+shortKey(w.signer("BB")))
		has(t, out, "earliest verified claim; rival unverified")
		has(t, out, "not evidence of copying")
		for _, bad := range []string{"could not have published", "proven later", "published later", "copied"} {
			hasNot(t, out, bad)
		}
	})
}

// TestDerivationGroupWithRealProofs: C-btc-26 (with C-core-20). Two derivers of W on the same inputs, verified at
// different heights by the real verifier: one group, derived by 2, no priority, explain says so.
func TestDerivationGroupWithRealProofs(t *testing.T) {
	conformance.Covers(t, "C-btc-26")
	w := newWorld(t)
	w.authored("wf:A", "A", "W", "type", "workflow", "replication", "bytes")
	w.authored("A1", "A", "X", "prov", []string{"W", "I"})
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X", "prov", []string{"W", "I"})
	w.anchorAt("BA", "BB", 20)
	v := w.chain(40).fresh(w.blobs)
	if ea, eb := v.Evaluate(w.sts["AA"]), v.Evaluate(w.sts["BA"]); !ea.Live() || !eb.Live() || Compare(ea, eb, 0) != EarlierCommitment {
		t.Fatalf("control: the members carry ranked bounds: %s / %s", ea, eb)
	}
	everyOrder(t, w, "X", v, func(a *resolveArtifact) {
		out := a.Render()
		if a.State != resolve.Derived {
			t.Fatalf("%s", out)
		}
		has(t, out, "derived by 2 under wf-")
		has(t, out, "priority is not computed within a derivation group")
		hasNot(t, out, "default author")
		hasNot(t, out, "later claimant")
	})
}

// TestReorg: C-btc-24 (without the receipt cache). A tip extension keeps the verdict; a reorg that orphans the
// attested block removes live quality at once (orphaned, local, no priority); a reorg back restores it. Nothing is
// grandfathered: every verdict is re-derived from the current snapshot.
func TestReorg(t *testing.T) {
	conformance.Partial(t, "C-btc-24", "verdicts re-derived per snapshot, so nothing survives a reorg; the receipt cache of note §9 (re-check only on a tip extension, a cached branch never surviving) is not built")
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.anchorAt("BA", "BB", 12)
	s := w.chain(20)
	v := s.fresh(w.blobs)
	if e := v.Evaluate(w.sts["AA"]); !e.Live() {
		t.Fatalf("before: %s", e)
	}
	epoch := v.View.Epoch
	s.extend(v.View.TipHash, 3, 0, "")
	v = s.fresh(w.blobs)
	if e := v.Evaluate(w.sts["AA"]); !e.Live() || e.Confirmations != 14 || e.ChainEpoch == epoch {
		t.Fatalf("tip extension: %s", e)
	}
	// a heavier branch from block 9 without A's root at 10 (B's root at 12 is carried along)
	h9, _ := v.View.HeaderAt(9)
	saved := s.roots[10]
	delete(s.roots, 10)
	s.extend(h9.Hash, 30, 0, "fork")
	s.roots[10] = saved
	v = s.fresh(w.blobs)
	e := v.Evaluate(w.sts["AA"])
	if e.State != StateOrphaned || e.Live() {
		t.Fatalf("after the reorg: %s", e)
	}
	if eb := v.Evaluate(w.sts["BA"]); !eb.Live() {
		t.Fatalf("B's block is on the new branch too: %s", eb)
	}
	a := w.resolver(nil, v).Artifact(dig("X"))
	if a.Default == nil || a.Default.Claims[0].Signer != w.signer("BB") {
		t.Fatalf("after the reorg, A's orphaned bound still ranks:\n%s", a.Render())
	}
	has(t, a.Render(), "orphaned")
}

// TestReceiptShapedInputGrantsNothing: C-btc-20 (statement half). A received statement carrying receipt-shaped
// fields (verified: true, quality: bitcoin, a block height) grants nothing; a statement of an unknown "receipt"
// kind is not an anchor. Bounds come from this reader's own evaluation only.
func TestReceiptShapedInputGrantsNothing(t *testing.T) {
	conformance.Partial(t, "C-btc-20", "received statements shaped like receipts grant nothing; a receipt-shaped file in the receipt store needs the store (note §9), not built")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	w.sign("AR", "A", "receipt", obj("covered", w.head["A"], "quality", "bitcoin", "verified", true, "block_height", 3))
	d := w.blobs.Put([]byte("not a proof"))
	w.sign("AA", "A", "anchors", obj("covered", w.ids["A1"], "proof", d, "proof_format", ProofFormat, "x_verified", true, "x_quality", "bitcoin"))
	w.authored("B1", "BB", "X")
	v := w.chain(30).fresh(w.blobs)
	a := w.resolver(nil, v).Artifact(dig("X"))
	if a.Default != nil {
		t.Fatalf("a receipt-shaped field ranked:\n%s", a.Render())
	}
	hasNot(t, a.Render(), "bitcoin testchain")
}

// TestNoNetworkInVerifier: C-btc-25 (verifier half). The package that evaluates bounds imports no network package
// (checked statically over its non-test sources); evaluation reads the snapshot and the blob source only.
func TestNoNetworkInVerifier(t *testing.T) {
	conformance.Partial(t, "C-btc-25", "the verifier package imports no network package; the status/verify/settlement commands and a process-level network audit are not built")
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		pf, err := goparser.ParseFile(fset, f, nil, goparser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range pf.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "syscall" {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if len(files) < 5 {
		t.Fatalf("found %d files; run from the package directory", len(files))
	}
}

// TestVerifierAbsent: C-btc-30 (resolver half). With no verifier for the profile (the resolver's default), every
// anchor is a local bound, nothing ranks, and every other answer is unchanged.
func TestVerifierAbsent(t *testing.T) {
	conformance.Partial(t, "C-btc-30", "the resolver's default verifier leaves every bound local and changes nothing else; a profile declaration reporting unsupported and the commands are not built")
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.authored("A2", "A", "Y")
	r := resolve.New(w.logs(nil))
	a := r.Artifact(dig("X"))
	if a.Default != nil || exitOf(a) != 3 {
		t.Fatalf("%s", a.Render())
	}
	has(t, a.Render(), "(local, self-declared)")
	if y := r.Artifact(dig("Y")); y.State != resolve.SoleAuthor || exitOf(y) != 0 {
		t.Fatalf("%s", y.Render())
	}
}

// TestAnchorWithoutCoveredInPrefix: C-btc-09. An anchors statement whose covered head is a line of the signer's own
// log that the anchor does not reach (a sibling branch) is refused (intrinsic, invalid-anchor), scoped to the
// statement: it bounds nothing even though its proof itself verifies, and the rest of the log is untouched.
// (The keylog test pins the boundary of "in the prefix"; this is the same refusal seen through the resolver.)
func TestAnchorWithoutCoveredInPrefix(t *testing.T) {
	conformance.Covers(t, "C-btc-09")
	w := newWorld(t)
	w.authored("A0", "A", "Y")
	fork, seq := w.head["A"], w.seq["A"]
	side := w.authored("A1", "A", "X")
	w.head["A"], w.seq["A"] = fork, seq
	cov := unhex(t, side)
	w.roots[5] = sha(cov, nonce("AA"))
	d := w.blobs.Put(otsFile(cov, opAppendB(nonce("AA")), opSHA256B(), attBitcoin(5)))
	w.sign("AA", "A", "anchors", obj("covered", side, "proof", d, "proof_format", ProofFormat))
	v := w.chain(20).fresh(w.blobs)
	if e := v.Evaluate(w.sts["AA"]); !e.Live() {
		t.Fatalf("control: the proof itself verifies: %s", e)
	}
	for _, order := range orders(len(w.lines), 9) {
		r := w.resolver(order, v)
		if a := r.Artifact(dig("X")); a.Claims[0].Bound.Quality != resolve.NoBound {
			t.Fatalf("an anchor bounded a line off its prefix: %s", a.Claims[0].Bound)
		}
		if p, _ := r.Statement(w.ids["A0"]); !p.Counts() {
			t.Fatal("the log's other statement no longer counts")
		}
		if p, ok := r.Statement(w.ids["AA"]); ok && p.Counts() {
			t.Fatal("the anchor itself still counts")
		}
	}
	var refused []keylog.Refused
	for _, rf := range w.logs(nil).Log(w.signer("A")).View().Refused {
		refused = append(refused, rf)
	}
	if len(refused) != 1 || refused[0].St.ID != w.ids["AA"] || refused[0].Reason.Class != refusal.Intrinsic || refused[0].Reason.Reason != refusal.InvalidAnchor {
		t.Fatalf("anchor not refused as intrinsic invalid-anchor: %v", refused)
	}
}
