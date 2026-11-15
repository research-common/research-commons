package btctime

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/refusal"
)

// mockUpgrader answers from a table keyed by commitment; a missing key is "still pending".
type mockUpgrader struct {
	uri     string
	answers map[string][]byte
	err     error
	asked   int
}

func (m *mockUpgrader) URI() string { return m.uri }

func (m *mockUpgrader) Upgrade(c []byte) ([]byte, error) {
	m.asked++
	if m.err != nil {
		return nil, m.err
	}
	if b, ok := m.answers[string(c)]; ok {
		return b, nil
	}
	return nil, ErrStillPending
}

const alice = "https://alice.btc.calendar.opentimestamps.org"

// TestUpgradeProofReference: UpgradeProof over the real pending proof and the calendar's real answer writes the
// reference client's upgraded file byte for byte, names the calendar in services and reports the height. The
// configured URL matches the proof's URI with or without one trailing slash.
func TestUpgradeProofReference(t *testing.T) {
	pfile := fixtureSHA(t, "incomplete.txt.ots", shaIncomplete)
	answer := fixtureSHA(t, "incomplete-upgrade-428648.bin", shaUpgrade)
	want := fixtureSHA(t, "incomplete-upgraded.txt.ots", shaUpgraded)
	tr, _ := ParseTree(pfile, Limits{})
	commitment := PendingCommitments(tr)[0].Commitment
	for _, configured := range []string{alice, alice + "/"} {
		cal := &mockUpgrader{uri: configured, answers: map[string][]byte{string(commitment): answer}}
		res, err := UpgradeProof(pfile, map[string]Upgrader{TrimCalendarURI(configured): cal}, false, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(res.Proof, want) || len(res.Services) != 1 || res.Services[0] != configured ||
			len(res.Heights) != 1 || res.Heights[0] != 428648 || res.HadBitcoin || res.Contacted != 1 {
			t.Fatalf("%s: %+v", configured, res)
		}
		if len(res.Asks) != 1 || res.Asks[0].Result != AskAnswered {
			t.Fatalf("asks %+v", res.Asks)
		}
	}
	// upgrading the upgraded proof again: the calendar answers the same, nothing new is gained
	cal := &mockUpgrader{uri: alice, answers: map[string][]byte{string(commitment): answer}}
	res, err := UpgradeProof(want, map[string]Upgrader{alice: cal}, false, Limits{})
	if err != nil || res.Proof != nil || !res.HadBitcoin || res.Asks[0].Result != AskAnswered {
		t.Fatalf("second upgrade: %v %+v", err, res)
	}
}

// TestUpgradeProofOutcomes: each outcome of one question, and that it is scoped to its calendar.
func TestUpgradeProofOutcomes(t *testing.T) {
	multi := fixtureSHA(t, "multi.txt.ots", shaMulti)
	tr, _ := ParseTree(multi, Limits{})
	pcs := PendingCommitments(tr)
	byURI := map[string][]byte{}
	for _, pc := range pcs {
		byURI[pc.URI] = pc.Commitment
	}
	bob, finney := "https://bob.btc.calendar.opentimestamps.org", "https://finney.calendar.eternitywall.com"
	answerFor := func(h uint64) []byte { return cat(opSHA256B(), attBitcoin(h)) }

	// not configured: reported, nothing asked
	res, err := UpgradeProof(multi, map[string]Upgrader{}, false, Limits{})
	if err != nil || res.Contacted != 0 || len(res.Asks) != 3 || res.Proof != nil {
		t.Fatalf("no policy: %v %+v", err, res)
	}
	for _, a := range res.Asks {
		if a.Result != AskNotInPolicy {
			t.Fatalf("%+v", a)
		}
	}
	// dry run: configured calendars are listed as "would ask", none is called
	m := &mockUpgrader{uri: bob}
	res, _ = UpgradeProof(multi, map[string]Upgrader{bob: m}, true, Limits{})
	if m.asked != 0 || res.Contacted != 0 {
		t.Fatalf("dry run asked: %+v", res)
	}
	got := map[string]AskResult{}
	for _, a := range res.Asks {
		got[a.URI] = a.Result
	}
	if got[bob] != AskDryRun || got[alice] != AskNotInPolicy || got[finney] != AskNotInPolicy {
		t.Fatalf("dry run asks %v", got)
	}
	// alice pending (404), bob failed, finney answers with an answer rooted elsewhere (refused, scoped): nothing new
	cals := map[string]Upgrader{
		alice:  &mockUpgrader{uri: alice},
		bob:    &mockUpgrader{uri: bob, err: errors.New("HTTP 500")},
		finney: &mockUpgrader{uri: finney, answers: map[string][]byte{string(byURI[finney]): {0xff}}},
	}
	res, err = UpgradeProof(multi, cals, false, Limits{})
	if err != nil || res.Proof != nil || res.Contacted != 3 || res.Pending != 1 || res.Failed != 2 {
		t.Fatalf("mixed: %v %+v", err, res)
	}
	// finney answers well, bob still fails: the proof gains a Bitcoin attestation; services names finney only
	cals[finney] = &mockUpgrader{uri: finney, answers: map[string][]byte{string(byURI[finney]): answerFor(700)}}
	res, err = UpgradeProof(multi, cals, false, Limits{})
	if err != nil || res.Proof == nil || len(res.Services) != 1 || res.Services[0] != finney || res.Heights[0] != 700 || res.Failed != 1 {
		t.Fatalf("one answered: %v %+v", err, res)
	}
	p, err := ParseProof(res.Proof, Limits{})
	if err != nil || p.PendingCount != 3 || len(p.Bitcoin) != 1 {
		t.Fatalf("merged: %v %+v", err, p)
	}
	// bob answers with trailing bytes after a valid answer (refused by the strict parser), finney answers well: the
	// refusal is scoped to bob and finney's answer is still merged
	cals = map[string]Upgrader{
		bob:    &mockUpgrader{uri: bob, answers: map[string][]byte{string(byURI[bob]): append(append([]byte{}, answerFor(5)...), 0x00)}},
		finney: &mockUpgrader{uri: finney, answers: map[string][]byte{string(byURI[finney]): answerFor(701)}},
	}
	res, err = UpgradeProof(multi, cals, false, Limits{})
	if err != nil || res.Proof == nil || res.Failed != 1 {
		t.Fatalf("trailing bytes scoped to bob: %v %+v", err, res)
	}
	for _, a := range res.Asks {
		if a.URI == bob && (a.Result != AskRefused || a.Err == nil) {
			t.Fatalf("bob %+v", a)
		}
	}
}

// prune keeps only the path from the root to the pending attestation naming uri.
func prune(n *Node, uri string) (*Node, bool) {
	out := &Node{Msg: n.Msg}
	for _, a := range n.Attestations {
		if a.Tag == TagPending {
			if u, ok := payloadVarbytes(a.Payload); ok && string(u) == uri {
				out.Attestations = append(out.Attestations, a)
			}
		}
	}
	for _, o := range n.Ops {
		if c, ok := prune(o.Child, uri); ok {
			out.Ops = append(out.Ops, TreeOp{Tag: o.Tag, Arg: o.Arg, Child: c})
		}
	}
	return out, len(out.Attestations)+len(out.Ops) > 0
}

// TestUnionProofsReference: the reference client's three-calendar proof, cut into the three single-calendar proofs
// each calendar's answer would have made, is rebuilt byte for byte by UnionProofs in any order.
func TestUnionProofsReference(t *testing.T) {
	multi := fixtureSHA(t, "multi.txt.ots", shaMulti)
	tr, _ := ParseTree(multi, Limits{})
	var parts [][]byte
	for _, pc := range PendingCommitments(tr) {
		r, _ := prune(tr.Root, pc.URI)
		one := (&Tree{FileDigest: tr.FileDigest, Root: r}).Serialize()
		if p, err := ParseProof(one, Limits{}); err != nil || p.PendingCount != 1 {
			t.Fatalf("part %s: %v", pc.URI, err)
		}
		parts = append(parts, one)
	}
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 0, 2}} {
		in := [][]byte{parts[order[0]], parts[order[1]], parts[order[2]]}
		got, err := UnionProofs(in, Limits{})
		if err != nil || !bytes.Equal(got, multi) {
			t.Fatalf("order %v: %v\n got %x\nwant %x", order, err, got, multi)
		}
	}
	if got, _ := UnionProofs(parts[:1], Limits{}); !bytes.Equal(got, parts[0]) {
		t.Fatal("one proof is not returned unchanged")
	}
	// proofs rooted at different digests are refused
	other := fixtureFile(t, "incomplete.txt.ots")
	_, err := UnionProofs([][]byte{parts[0], other}, Limits{})
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Reason != refusal.UpgradeRootedElsewhere || !strings.Contains(r.Detail, "proof 2") {
		t.Fatalf("different roots: %v", err)
	}
	if _, err := UnionProofs(nil, Limits{}); err == nil {
		t.Fatal("no proofs accepted")
	}
}
