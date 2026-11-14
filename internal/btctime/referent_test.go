package btctime

import (
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

func exactBytes(class, chain, hash string) *wire.Statement {
	ref := &canon.Object{Members: map[string]canon.Value{"chain_id": canon.String(chain), "block_hash": canon.String(hash), "depth": canon.Int(3)}}
	return &wire.Statement{Body: &canon.Object{Members: map[string]canon.Value{"class": canon.String(class), "referent": ref}}}
}

// TestReferentCheckerPosition: the header-chain referent checker reads position only. On the accepted chain it gives
// RePosition at tip - height + 1; on a losing branch, not canonical; on one of two tips tied at the greatest work,
// unchecked (unresolved); a block not held, another chain id, a non-exact-bytes class, a malformed hash and a view
// never synced are unchecked, naming why. It never reports identical or different bytes.
func TestReferentCheckerPosition(t *testing.T) {
	p := testParams("refcheck", 0x207fffff)
	s := newSynth(t, p)
	base := s.extend(s.genesis(), 3, 0, "") // heights 1..3
	short := s.extend(base, 2, 0, "short")  // 4..5, losing
	long := s.extend(base, 4, 0, "long")    // 4..7, accepted
	unsynced := ReferentChecker{View: s.c.Snapshot(), Policy: s.policy()}
	vf := s.fresh(nil)
	c := ReferentChecker{View: vf.View, Policy: vf.Policy, Now: vf.Now}
	id := c.View.ChainID()
	check := func(st *wire.Statement) resolve.ReCheck {
		rc := c.Check(st)
		if rc.Outcome == resolve.ReSame || rc.Outcome == resolve.ReDifferent || rc.Digest != "" {
			t.Fatalf("a position checker reported bytes: %+v", rc)
		}
		return rc
	}
	if rc := check(exactBytes("exact-bytes", id, long.String())); rc.Outcome != resolve.RePosition || !rc.PositionOnly || rc.State != (resolve.State{HasDepth: true, Depth: 1}) {
		t.Fatalf("tip: %+v", rc)
	}
	if rc := check(exactBytes("exact-bytes", id, base.String())); rc.Outcome != resolve.RePosition || rc.State.Depth != 5 {
		t.Fatalf("height 3 under tip 7: %+v", rc)
	}
	if rc := check(exactBytes("exact-bytes", id, short.String())); rc.Outcome != resolve.ReNotCanonical || !strings.Contains(rc.Why, "held off the accepted chain") {
		t.Fatalf("losing branch: %+v", rc)
	}
	for name, tc := range map[string]struct {
		st  *wire.Statement
		why string
	}{
		"not held":     {exactBytes("exact-bytes", id, strings.Repeat("ab", 32)), "block not in this reader's header chain"},
		"other chain":  {exactBytes("exact-bytes", "bip122:000000000019d6689c085ae165831e93", long.String()), "is not this reader's header chain"},
		"eip155 chain": {exactBytes("exact-bytes", "eip155:1", long.String()), "is not this reader's header chain"},
		"bad hash":     {exactBytes("exact-bytes", id, "zz"), "not a display-order block hash"},
		"source class": {exactBytes("source", id, long.String()), "exact-bytes referents only"},
	} {
		if rc := check(tc.st); rc.Outcome != resolve.ReUnchecked || !strings.Contains(rc.Why, tc.why) {
			t.Fatalf("%s: %+v", name, rc)
		}
	}
	if rc := unsynced.Check(exactBytes("exact-bytes", id, long.String())); rc.Outcome != resolve.ReUnchecked || !strings.Contains(rc.Why, "never synced") {
		t.Fatalf("unsynced view: %+v", rc)
	}
	// an old view still answers, disclosing that it is not fresh
	late := c
	late.Now = func() time.Time { return vf.Now().Add(3 * time.Hour) }
	if rc := late.Check(exactBytes("exact-bytes", id, base.String())); rc.Outcome != resolve.RePosition || !strings.Contains(rc.Why, "not fresh") {
		t.Fatalf("stale view: %+v", rc)
	}
	// two tips tied at the greatest work: a block above the fork point is unresolved, not orphaned
	tie := s.extend(base, 4, 0, "tie") // 4..7 again, equal work to long
	vt := s.fresh(nil)
	ct := ReferentChecker{View: vt.View, Policy: vt.Policy, Now: vt.Now}
	if vt.View.Unresolved == 0 {
		t.Fatal("fixture: no tie")
	}
	for _, h := range []Hash{long, tie} {
		if rc := ct.Check(exactBytes("exact-bytes", id, h.String())); rc.Outcome != resolve.ReUnchecked || !strings.Contains(rc.Why, "tied at the greatest chainwork") {
			t.Fatalf("tied tip: %+v", rc)
		}
	}
	if rc := ct.Check(exactBytes("exact-bytes", id, base.String())); rc.Outcome != resolve.RePosition || rc.State.Depth != 1 {
		t.Fatalf("fork point under a tie: %+v", rc)
	}
}
