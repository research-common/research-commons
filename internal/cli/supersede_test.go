package cli

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
)

// anchorHead signs an anchors statement by n over head (not necessarily n's current head) with a parsing proof
// whose one Bitcoin attestation names height: with no chain backend it is backend-unconfigured, quality local.
func (w *world) anchorHead(name, n, head string, height uint64) string {
	cov, _ := hex.DecodeString(head)
	att := append([]byte{0x00}, btctime.TagBitcoin[:]...)
	payload := uvar(height)
	att = append(att, append(uvar(uint64(len(payload))), payload...)...)
	proof := append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), cov...)
	proof = append(proof, att...)
	d := w.blob("proof:"+name, proof)
	return w.sign(name, n, "anchors", obj("covered", head, "proof", d, "proof_format", btctime.ProofFormat))
}

// anchorRows is explain's `anchors` member: anchor id → the row, or nil when the member is absent.
func anchorRows(t *testing.T, o *canon.Object) map[string]*canon.Object {
	t.Helper()
	l, ok := o.Members["anchors"].(canon.Array)
	if !ok {
		return nil
	}
	out := map[string]*canon.Object{}
	for _, e := range l {
		r := e.(*canon.Object)
		out[string(r.Members["anchor"].(canon.String))] = r
	}
	return out
}

// TestExplainListsSupersededAnchors: bitcoin-time note §1 rule 5 through the commands. One head stamped twice:
// the claimant's time names the later anchors line; explain of the blob, of the authored statement and of
// either anchors line lists both lines with their state, marks the later one displayed and the earlier one
// "superseded by" it; both are inputs of the answer. With one anchors line explain prints no `anchors` member,
// so that answer is as before.
func TestExplainListsSupersededAnchors(t *testing.T) {
	conformance.Covers(t, "C-btc-31")
	w := newWorld(t)
	h := w.authored("A1", "A", "X")
	single := w.anchorHead("AA1", "A", h, 100)
	one := jsonOf(t, w.run("explain", dig("X"), "--json"))
	if _, ok := one.Members["anchors"]; ok {
		t.Fatalf("one anchors line: explain prints an anchors member: %s", canon.Encode(one.Members["anchors"]))
	}
	oneHuman := w.run("explain", dig("X")).stdout
	if strings.Contains(oneHuman, "displayed") {
		t.Fatalf("one anchors line, human explain: %s", oneHuman)
	}

	later := w.anchorHead("AA2", "A", h, 101)
	claim := jsonOf(t, w.run("show", dig("X"), "--json")).Members["claimants"].(canon.Array)[0].(*canon.Object)
	if tm := string(canon.Encode(claim.Members["time"])); !strings.Contains(tm, `"anchor":"`+later+`"`) || !strings.Contains(tm, `"quality":"local"`) {
		t.Fatalf("claimant time after a second stamp: %s", tm)
	}
	for _, ref := range []string{dig("X"), h, single, later} {
		o := jsonOf(t, w.run("explain", ref, "--json"))
		rows := anchorRows(t, o)
		if len(rows) != 2 {
			t.Fatalf("explain %s: %d anchors rows, want 2 (both lines of the head listed)", keylog.Short(ref), len(rows))
		}
		lr, er := rows[later], rows[single]
		if lr == nil || er == nil || lr.Members["displayed"] != canon.Bool(true) || er.Members["displayed"] != canon.Bool(false) {
			t.Fatalf("explain %s: %s", keylog.Short(ref), canon.Encode(o.Members["anchors"]))
		}
		if lr.Members["why"] != canon.String("latest in log order") ||
			er.Members["why"] != canon.String("superseded by "+keylog.Short(later)) {
			t.Fatalf("explain %s, why: %s", keylog.Short(ref), canon.Encode(o.Members["anchors"]))
		}
		for _, r := range []*canon.Object{lr, er} {
			if r.Members["quality"] != canon.String("local") || r.Members["time_state"] != canon.String(string(btctime.StateUnconfigured)) ||
				r.Members["covered"] != canon.String(h) {
				t.Fatalf("explain %s, row: %s", keylog.Short(ref), canon.Encode(r))
			}
		}
		in := explainInputs(t, "x "+w.run("explain", ref, "--json").stdout)
		for _, id := range []string{single, later} {
			if !strings.Contains(strings.Join(in, " "), id) {
				t.Fatalf("explain %s: anchors line %s is not an input %v", keylog.Short(ref), keylog.Short(id), in)
			}
		}
	}
	human := w.run("explain", dig("X")).stdout
	for _, s := range []string{"latest in log order", "superseded by " + keylog.Short(later)} {
		if !strings.Contains(human, s) {
			t.Fatalf("human explain lacks %q:\n%s", s, human)
		}
	}
	// verify is unchanged: a sole author needs no bound
	if r := w.run("verify", dig("X"), "--json"); r.code != 0 {
		t.Fatalf("verify: %d %s", r.code, r.stdout)
	}
}
