package btctime

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// TestPreRegistrationBound: C-btc-28. A result `fulfills` a task edition; the edition's approval is anchored.
// Through this package's verifier, the resolver's pre-registration line reads the same evidence record as
// priority and capture evidence (I12): with no chain evidence it is `(local, self-declared)`; with the anchor's
// block on a verified chain it is `(bitcoin)` with the height, never a bare time.
func TestPreRegistrationBound(t *testing.T) {
	conformance.Covers(t, "C-btc-28")
	w := newWorld(t)
	w.sign("G", "R", "genesis", obj("type", "task", "name", "t", "controllers", []string{w.signer("R")}, "rule", canon.Value(obj("any_one", true))))
	body := obj("resource", w.ids["G"], "predecessors", []string{w.ids["G"]}, "contents", canon.Value(obj()))
	w.sign("E", "R", "edition", body)
	ed := resolve.EditionID(body)
	w.anchorAt("AR", "R", 10)
	w.authored("X", "A", "RES", "fulfills", canon.Value(obj("resource", w.ids["G"], "edition", ed)))
	verified := w.chain(30).fresh(w.blobs)
	local := &Verifier{Policy: DefaultPolicy(), Blobs: w.blobs}
	for _, c := range []struct {
		v    *Verifier
		want string
	}{
		{verified, "pre-registered " + ed[:12] + " (bitcoin) at "},
		{local, "pre-registered " + ed[:12] + " (local, self-declared)"},
	} {
		p, ok := w.resolver(nil, c.v).PreRegistration(w.ids["X"])
		if !ok || !strings.HasPrefix(p.Display, c.want) {
			t.Fatalf("display %q, want prefix %q", p.Display, c.want)
		}
		if c.v == verified && !strings.Contains(p.Display, "height 10") {
			t.Fatalf("verified display without height: %q", p.Display)
		}
		if c.v == local && strings.Contains(p.Display, "height") {
			t.Fatalf("local display carries a height: %q", p.Display)
		}
	}
}
