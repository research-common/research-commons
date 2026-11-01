package btctime

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// TestHistoricalMainnetProof: note §13 item 8. The public hello-world proof, checked against the real header chain:
// verified at block 358 391 with the hash, Merkle root and nTime two explorers report, and the Merkle root
// independently recomputed from the block's 1433 transaction ids. The library's bad-stamp example, claiming the
// same block, is invalid-proof. Stamped digest = sha256 of the example file, so this exercises EvaluateProof (the
// anchors path differs only in where the digest comes from, tested on synthetic chains below).
func TestHistoricalMainnetProof(t *testing.T) {
	c, now := mainnetChain(t, fixtureTip)
	v := &Verifier{Policy: DefaultPolicy(), View: c.Snapshot(), Now: func() time.Time { return now }}
	e := v.EvaluateProof(fixtureFile(t, "hello-world.txt.ots"), unhex(t, helloDigest))
	if !e.Live() || e.BlockHeight != 358391 || e.BlockHash != "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319" ||
		e.HeaderTime != 1432827678 || e.Confirmations != fixtureTip-358391+1 || e.ChainValidation != ModeHeadersSPV {
		t.Fatalf("%+v", e)
	}
	if !strings.Contains(e.Bootstrap, "bootstrap:sha256:") {
		t.Fatalf("bootstrap identity not disclosed: %q", e.Bootstrap)
	}
	// independent cross-check: the Merkle root from the block's txids
	h, _ := v.View.HeaderAt(358391)
	if got := merkleFromTxids(t, fixtureFile(t, "mainnet-358391.txids")); got != h.MerkleRoot {
		t.Fatalf("txid Merkle root %s, header %s", got, h.MerkleRoot)
	}
	// the library's bad-stamp example
	bad := v.EvaluateProof(fixtureFile(t, "bad-stamp.txt.ots"), unhex(t, "7e3717bbe020f53cdc6c40154a1a8e55bddc13a28c8bb3c82e9ee64b81b44872"))
	if bad.State != StateInvalidProof || !strings.Contains(bad.Why, "Merkle root") {
		t.Fatalf("bad stamp: %s", bad)
	}
	// the right proof for the wrong digest fails check 7
	if e := v.EvaluateProof(fixtureFile(t, "hello-world.txt.ots"), sha([]byte("other"))); e.State != StateInvalidProof {
		t.Fatalf("wrong digest: %s", e)
	}
	// a view that ends before 358 391 + 5 has insufficient confirmations; before 358 391, unknown height
	c2, now2 := mainnetChain(t, 358395)
	v2 := &Verifier{Policy: DefaultPolicy(), View: c2.Snapshot(), Now: func() time.Time { return now2 }}
	if e := v2.EvaluateProof(fixtureFile(t, "hello-world.txt.ots"), unhex(t, helloDigest)); e.State != StateInsufficient || e.Confirmations != 5 {
		t.Fatalf("5 confirmations: %s", e)
	}
	c3, now3 := mainnetChain(t, 358000)
	v3 := &Verifier{Policy: DefaultPolicy(), View: c3.Snapshot(), Now: func() time.Time { return now3 }}
	if e := v3.EvaluateProof(fixtureFile(t, "hello-world.txt.ots"), unhex(t, helloDigest)); e.State != StateUnknownHeight {
		t.Fatalf("beyond the tip: %s", e)
	}
}

func merkleFromTxids(t *testing.T, b []byte) Hash {
	var level [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		h, err := ParseDisplayHash(sc.Text())
		if err != nil {
			t.Fatal(err)
		}
		level = append(level, append([]byte{}, h[:]...))
	}
	if len(level) != 1433 {
		t.Fatalf("%d txids", len(level))
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			d := dsha256(append(append([]byte{}, level[i]...), level[i+1]...))
			next = append(next, d[:])
		}
		level = next
	}
	return Hash(level[0])
}

// TestConfirmations: C-btc-17. 5 confirmations → insufficient-confirmations; 6 → verified.
func TestConfirmations(t *testing.T) {
	conformance.Covers(t, "C-btc-17")
	for _, c := range []struct {
		tip   int64
		state State
	}{{14, StateInsufficient}, {15, StateVerified}} {
		w := newWorld(t)
		w.authored("A1", "A", "X")
		w.anchorAt("AA", "A", 10)
		v := w.chain(c.tip).fresh(w.blobs)
		if e := v.Evaluate(w.sts["AA"]); e.State != c.state || e.Confirmations != c.tip-9 {
			t.Fatalf("tip %d: %s", c.tip, e)
		}
	}
}

// TestSettledDepth: C-btc-17a. An old snapshot (past the maximum view age): 143 confirmations in it →
// verified-historical, time shown as of the sync, no priority, exit 3; 144 → verified, bitcoin, as of the sync,
// ranks, exit 0; with minimum confirmations 200 both are insufficient-confirmations.
func TestSettledDepth(t *testing.T) {
	conformance.Covers(t, "C-btc-17a")
	for _, c := range []struct {
		tip     int64
		minConf int64
		state   State
		exit    int
	}{{152, 6, StateVerifiedHistorical, 3}, {153, 6, StateVerified, 0}, {152, 200, StateInsufficient, 3}, {153, 200, StateInsufficient, 3}} {
		w := newWorld(t)
		w.authored("A1", "A", "X", "licence", "CC0-1.0")
		w.anchorAt("AA", "A", 10)
		w.authored("B1", "BB", "X", "licence", "MIT")
		s := w.chain(c.tip)
		v := s.fresh(w.blobs)
		sync := v.View.LastSync
		later := sync.Add(30 * 24 * time.Hour)
		v.Now = func() time.Time { return later }
		v.Policy.MinConfirmations = c.minConf
		e := v.Evaluate(w.sts["AA"])
		if e.State != c.state || Exit([]Evidence{e}) != c.exit {
			t.Fatalf("tip %d min %d: %s (exit %d)", c.tip, c.minConf, e, Exit([]Evidence{e}))
		}
		a := w.resolver(nil, v).Artifact(dig("X"))
		out := a.Render()
		switch c.state {
		case StateVerifiedHistorical:
			has(t, e.String(), "as of "+sync.UTC().Format(time.RFC3339))
			has(t, e.String(), "header time")
			has(t, out, "verified-historical")
			if a.Default != nil || exitOf(a) != 3 {
				t.Fatalf("historical ranked:\n%s", out)
			}
		case StateVerified:
			has(t, e.String(), "as of "+sync.UTC().Format(time.RFC3339))
			if a.Default == nil || a.Default.Claims[0].Signer != w.signer("A") || exitOf(a) != 0 {
				t.Fatalf("settled bound did not rank:\n%s", out)
			}
		default:
			if a.Default != nil {
				t.Fatalf("insufficient ranked:\n%s", out)
			}
		}
	}
}

// TestPriorityMargin: C-btc-17b. Verified at n and n+3: margin 0 → earlier-commitment, default author; margin 3 →
// within-margin, contested, exit 3, explain names the gap and the margin.
func TestPriorityMargin(t *testing.T) {
	conformance.Covers(t, "C-btc-17b")
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.anchorAt("BA", "BB", 13)
	s := w.chain(40)
	for _, c := range []struct {
		margin int64
		want   string
		exit   int
	}{{0, "earlier-commitment", 0}, {3, "within-margin (gap 3, margin 3)", 3}, {2, "earlier-commitment", 0}} {
		v := s.fresh(w.blobs)
		v.Policy.PriorityMargin = c.margin
		everyOrder(t, w, "X", v, func(a *resolveArtifact) {
			out := a.Render()
			has(t, out, c.want)
			if exitOf(a) != c.exit || (c.exit == 0) != (a.Default != nil) {
				t.Fatalf("margin %d:\n%s", c.margin, out)
			}
			if c.exit == 3 {
				has(t, out, "contested")
			}
		})
		ea, eb := v.Evaluate(w.sts["AA"]), v.Evaluate(w.sts["BA"])
		rel := Compare(ea, eb, c.margin)
		if (c.margin == 3) != (rel == WithinMargin) {
			t.Fatalf("margin %d: relation %s", c.margin, rel)
		}
	}
}

// TestStaleAndUnavailable: C-btc-18. Stale tip, old snapshot below settled depth, clock rollback, backend down:
// historical or local, never live. A snapshot that changes mid-batch is retried once, then incomplete.
func TestStaleAndUnavailable(t *testing.T) {
	conformance.Covers(t, "C-btc-18")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	w.anchorAt("AA", "A", 10)
	s := w.chain(30)
	base := s.fresh(w.blobs)
	if e := base.Evaluate(w.sts["AA"]); !e.Live() {
		t.Fatalf("control: %s", e)
	}
	tipTime := time.Unix(int64(base.View.TipTime), 0)
	for _, c := range []struct {
		name string
		mod  func(v *Verifier)
		want []State
	}{
		{"stale tip", func(v *Verifier) {
			// synced a minute ago, but the tip header is a day old: the sync found nothing new
			now := tipTime.Add(24 * time.Hour)
			s.c.MarkSynced(now.Add(-time.Minute))
			v.View = s.c.Snapshot()
			v.Now = func() time.Time { return now }
		}, []State{StateVerifiedHistorical}},
		{"old snapshot below settled depth", func(v *Verifier) {
			now := v.View.LastSync.Add(48 * time.Hour)
			v.Now = func() time.Time { return now }
		}, []State{StateVerifiedHistorical}},
		{"clock rollback", func(v *Verifier) {
			now := v.View.LastSync.Add(-time.Hour)
			v.Now = func() time.Time { return now }
		}, []State{StateStaleChain}},
		{"backend down", func(v *Verifier) { v.View, v.Unavailable = nil, "connection refused" }, []State{StateUnavailable}},
		{"never synced", func(v *Verifier) {
			c := *v.View
			c.LastSync = time.Time{}
			v.View = &c
		}, []State{StateStaleChain}},
	} {
		v := *s.fresh(w.blobs)
		c.mod(&v)
		e := v.Evaluate(w.sts["AA"])
		if e.Live() || !contains(c.want, e.State) {
			t.Fatalf("%s: %s", c.name, e)
		}
		a := w.resolver(nil, &v).Artifact(dig("X"))
		if a.Default != nil && a.State == "default author" {
			t.Fatalf("%s ranked", c.name)
		}
		hasNot(t, a.Render(), "bitcoin testchain")
	}
	// mid-batch change: a header added while the batch runs → one retry; changing on every run → incomplete
	calls := 0
	bs := &batchBlobs{inner: w.blobs, hook: func() {
		calls++
		s.extend(s.c.Snapshot().TipHash, 1, 0, "mid")
	}}
	_, err := Batch(s.c, Verifier{Policy: s.policy(), Blobs: bs, Now: base.Now}, []*wireStatement{w.sts["AA"]})
	if err != ErrIncomplete || calls != 2 {
		t.Fatalf("always changing: %v after %d runs", err, calls)
	}
	calls = 0
	once := &batchBlobs{inner: w.blobs, hook: func() {
		calls++
		if calls == 1 {
			s.extend(s.c.Snapshot().TipHash, 1, 0, "once")
		}
	}}
	s.c.MarkSynced(base.Now().Add(-time.Minute))
	es, err := Batch(s.c, Verifier{Policy: s.policy(), Blobs: once, Now: base.Now}, []*wireStatement{w.sts["AA"]})
	if err != nil || calls != 2 || len(es) != 1 || es[0].ChainEpoch != s.c.Epoch() {
		t.Fatalf("one change: %v, %d runs, %+v", err, calls, es)
	}
}

func contains(ss []State, s State) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// TestNoBackend: C-btc-06. A well-formed proof, no backend configured: unverified (local, self-declared), no
// priority, exit 3, both at the evidence and at the resolver; a quality label in the statement grants nothing.
func TestNoBackend(t *testing.T) {
	conformance.Covers(t, "C-btc-06")
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X", "licence", "MIT")
	// a received anchors statement claiming bitcoin quality in an extension field
	d := w.blobs.Put(otsFile(unhex(t, w.head["BB"]), opAppendB(nonce("BA")), opSHA256B(), attBitcoin(9)))
	w.sign("BA", "BB", "anchors", obj("covered", w.head["BB"], "proof", d, "proof_format", ProofFormat, "x_quality", "bitcoin"))
	// control: with a backend the proof verifies, so the mutation (no backend) is what changes the result
	if e := w.chain(30).fresh(w.blobs).Evaluate(w.sts["AA"]); !e.Live() {
		t.Fatalf("control: %s", e)
	}
	v := &Verifier{Policy: DefaultPolicy(), Blobs: w.blobs, Now: time.Now}
	e := v.Evaluate(w.sts["AA"])
	if e.State != StateUnconfigured || e.Quality != QualityLocal || Exit([]Evidence{e}) != 3 || !strings.Contains(e.Why, "not verified by this reader") {
		t.Fatalf("%s", e)
	}
	everyOrder(t, w, "X", v, func(a *resolveArtifact) {
		out := a.Render()
		has(t, out, "(local, self-declared)")
		has(t, out, "backend-unconfigured")
		hasNot(t, out, "bitcoin testchain")
		if a.Default != nil || exitOf(a) != 3 {
			t.Fatalf("%s", out)
		}
	})
}

// TestBindingChecks: C-btc-07, C-btc-08, C-btc-10, C-btc-12 (§4 checks 3, 4, 7; pending).
func TestBindingChecks(t *testing.T) {
	conformance.Covers(t, "C-btc-07", "C-btc-08", "C-btc-10", "C-btc-12")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	head := w.head["A"]
	cov := unhex(t, head)
	good := otsFile(cov, opAppendB(nonce("ok")), opSHA256B(), attBitcoin(5))
	w.roots[5] = sha(cov, nonce("ok"))
	w.anchorProof("OK", "A", good, ProofFormat)
	// every variant covers the same head: re-point the head before each
	variant := func(name string, proof []byte, format string) {
		w.head["A"] = head
		w.seq["A"] = 1
		w.anchorProof(name, "A", proof, format)
	}
	hexDigest := []byte(hex.EncodeToString(cov))
	variant("raw-of-other", otsFile(sha([]byte("another statement")), attBitcoin(5)), ProofFormat)
	variant("hex", cat(HeaderMagic, []byte{0x01, opSHA256}, sha(hexDigest), attBitcoin(5)), ProofFormat)
	variant("newline", otsFile(sha(append(append([]byte{}, cov...), '\n')), attBitcoin(5)), ProofFormat)
	variant("statement-bytes", otsFile(sha(w.lines[0]), attBitcoin(5)), ProofFormat)
	variant("format", good, "rfc3161-v1")
	variant("pending", otsFile(cov, attPending("https://alice.btc.calendar.opentimestamps.org")), ProofFormat)
	s := w.chain(20)
	v := s.fresh(w.blobs)
	if e := v.Evaluate(w.sts["OK"]); !e.Live() {
		t.Fatalf("control: %s", e)
	}
	for _, c := range []struct {
		name  string
		state State
		why   string
	}{
		{"raw-of-other", StateInvalidProof, "not the raw bytes of covered"},
		{"hex", StateInvalidProof, "not the raw bytes of covered"},
		{"newline", StateInvalidProof, "not the raw bytes of covered"},
		{"statement-bytes", StateInvalidProof, "not the raw bytes of covered"},
		{"format", StateUnsupported, "rfc3161-v1"},
		{"pending", StatePending, "calendar"},
	} {
		e := v.Evaluate(w.sts[c.name])
		if e.State != c.state || !strings.Contains(e.Why, c.why) || e.Live() {
			t.Fatalf("%s: %s", c.name, e)
		}
		if c.state == StateUnsupported && e.Refusal != nil {
			t.Fatalf("unsupported refused something: %v", e.Refusal)
		}
	}
	// C-btc-12: the pending URI is retained for display, and nothing dereferences it: the verifier has no network
	// path at all (no client, no dialer); the blob source is the only input it reads.
	p, _ := ParseProof(otsFile(cov, attPending("https://alice.btc.calendar.opentimestamps.org")), Limits{})
	if p.Pending[0].URI == "" {
		t.Fatal("pending URI not retained")
	}
	// C-btc-10: missing proof, no fetch attempted: the blob source records every request and is asked for the one
	// digest only
	missing := &countingBlobs{inner: MapBlobs{}}
	v.Blobs = missing
	e := v.Evaluate(w.sts["OK"])
	if e.State != StateMissingProof || Exit([]Evidence{e}) != 3 || !strings.Contains(e.Why, "no fetch attempted") || len(missing.asked) != 1 {
		t.Fatalf("missing: %s, asked %v", e, missing.asked)
	}
	// held bytes that do not hash to the digest are not the proof
	v.Blobs = MapBlobs{str(w.sts["OK"].Body, "proof"): []byte("corrupt")}
	if e := v.Evaluate(w.sts["OK"]); e.State != StateMissingProof {
		t.Fatalf("corrupt blob: %s", e)
	}
}

// TestAnchorRefusalsAreScoped: C-btc-05. A malformed and an oversized proof on an otherwise valid log: the anchor
// alone is refused, with its class named; the log's statements stay valid and displayed; no bound is derived.
func TestAnchorRefusalsAreScoped(t *testing.T) {
	conformance.Covers(t, "C-btc-05")
	for _, c := range []struct {
		name   string
		proof  func(cov []byte) []byte
		class  refusal.Class
		reason string
	}{
		{"malformed", func(cov []byte) []byte { return otsFile(cov, []byte{0x55}) }, refusal.Intrinsic, "invalid proof"},
		{"oversized", func(cov []byte) []byte { return append(otsFile(cov, attBitcoin(5)), make([]byte, 9<<20)...) }, refusal.Operational, refusal.SizeLimit},
	} {
		w := newWorld(t)
		w.authored("A1", "A", "X", "licence", "CC0-1.0")
		w.anchorProof("AA", "A", c.proof(unhex(t, w.head["A"])), ProofFormat)
		w.authored("A2", "A", "Y")
		w.authored("B1", "BB", "X", "licence", "MIT")
		w.anchorAt("BA", "BB", 6)
		v := w.chain(30).fresh(w.blobs)
		e := v.Evaluate(w.sts["AA"])
		if e.Refusal == nil || e.Refusal.Class != c.class || e.Refusal.Reason != c.reason || e.Quality == QualityBitcoin {
			t.Fatalf("%s: %+v", c.name, e)
		}
		r := w.resolver(nil, v)
		for _, n := range []string{"A1", "AA", "A2"} {
			if p, ok := r.Statement(w.ids[n]); !ok || !p.Counts() {
				t.Fatalf("%s: statement %s no longer counts", c.name, n)
			}
		}
		a := r.Artifact(dig("X"))
		out := a.Render()
		has(t, out, "refused")
		has(t, out, string(c.class))
		// B's verified bound outranks A's absent one: A got no bound from the refused anchor
		if a.Default == nil || a.Default.Claims[0].Signer != w.signer("BB") {
			t.Fatalf("%s:\n%s", c.name, out)
		}
		if y := r.Artifact(dig("Y")); y.State != "sole author" {
			t.Fatalf("%s: A's other statement: %s", c.name, y.Render())
		}
	}
}

// TestPerSignerProof: C-btc-04, the variant the resolver half could not reach: a proof that commits to B's prefix,
// attached as A's anchor covering A's own head. Invalid for A; B's line gets no bound from it; B's log untouched.
// (The first half, covered naming B's line, is the log's refusal: resolve.TestBoundsArePerSigner.)
func TestPerSignerProof(t *testing.T) {
	conformance.Covers(t, "C-btc-04")
	w := newWorld(t)
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.anchorAt("BA", "BB", 7) // B's honest anchor at 7
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	// A copies B's proof bytes (stamping B's head) under its own anchor
	w.sign("AA", "A", "anchors", obj("covered", w.head["A"], "proof", str(w.sts["BA"].Body, "proof"), "proof_format", ProofFormat))
	// and A lists B's line in an extension field of a second anchor: grants B nothing
	w.sign("AB", "A", "anchors", obj("covered", w.ids["A1"], "proof", str(w.sts["BA"].Body, "proof"), "proof_format", ProofFormat, "x_also", []string{w.ids["B1"]}))
	// and a third anchor whose covered IS B's line, with a proof that really stamps B's line: the log refuses it
	// (an anchor bounds only its signer's log), so it bounds nothing for anyone
	cb := unhex(t, w.ids["B1"])
	w.roots[8] = sha(cb, nonce("AC"))
	pc := w.blobs.Put(otsFile(cb, opAppendB(nonce("AC")), opSHA256B(), attBitcoin(8)))
	w.sign("AC", "A", "anchors", obj("covered", w.ids["B1"], "proof", pc, "proof_format", ProofFormat))
	v := w.chain(30).fresh(w.blobs)
	e := v.Evaluate(w.sts["AA"])
	if e.State != StateInvalidProof || !strings.Contains(e.Why, "invalid for "+w.signer("A")) {
		t.Fatalf("%s", e)
	}
	if e := v.Evaluate(w.sts["BA"]); !e.Live() {
		t.Fatalf("control, B's own anchor: %s", e)
	}
	// the proof itself is good: only the log's per-signer rule keeps AC from bounding B's line
	if e := v.Evaluate(w.sts["AC"]); !e.Live() {
		t.Fatalf("control, the proof stamping B's line: %s", e)
	}
	if av := w.logs(nil).Log(w.signer("A")).View(); len(av.Refused) != 1 || !strings.Contains(av.Refused[0].Reason.Detail, "an anchor bounds only its signer's log") {
		t.Fatalf("A's anchor covering B's line not refused: %s", av.Render())
	}
	everyOrder(t, w, "X", v, func(a *resolveArtifact) {
		out := a.Render()
		if a.Default == nil || a.Default.Claims[0].Signer != w.signer("BB") {
			t.Fatalf("%s", out)
		}
		has(t, out, "later claimant "+shortKey(w.signer("A"))+", bound no anchor (anchor ")
		has(t, out, "invalid-proof")
	})
	// B alone: its bound is from its own anchor only, unchanged by A's statements
	wb := newWorld(t)
	wb.authored("B1", "BB", "X", "licence", "MIT")
	wb.anchorAt("BA", "BB", 7)
	vb := wb.chain(30).fresh(wb.blobs)
	alone := wb.resolver(nil, vb).Artifact(dig("X"))
	with := w.resolver(nil, v)
	if bp, _ := with.Statement(w.ids["B1"]); !bp.Counts() {
		t.Fatal("B's line affected")
	}
	if alone.Claims[0].Bound.Height != 7 {
		t.Fatalf("B alone: %s", alone.Render())
	}
}

// shortKey mirrors the resolver's display of a key.
func shortKey(k string) string {
	if strings.HasPrefix(k, "ed25519:") && len(k) > 20 {
		return k[:20]
	}
	if len(k) > 14 {
		return k[:14]
	}
	return k
}
