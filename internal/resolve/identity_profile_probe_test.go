package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// unknownProfileOutcome signs an identity inception with the given profile (plus an optional extra inception
// member), a grant under it, and one act under that grant, then reads them through the candidate reader.
func unknownProfileOutcome(t *testing.T, profile string, extra bool) (inceptionStatus, inceptionWhy string, state string, why []string, refused int) {
	t.Helper()
	w := newWorld(t)
	w.authored("K0", "K", "K0")
	body := obj("profile", profile)
	if extra {
		body = withMember(body, "recovery", obj("commitment", "sha256:"+strings.Repeat("ab", 32)))
	}
	i := w.signRC2("I", "IR", "identity_inception", body, rc2MarkerOnly, [2]string{})
	perms := canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", false)}
	g := w.signRC2("G", "IR", "identity_grant", obj("identity", i, "delegate", obj("key", w.signer("K"), "inception", w.firstLine("K")), "permissions", perms), rc2MarkerOnly, [2]string{})
	a := w.signRC2("A", "K", "authored", obj("content", contentOf("Y"), "type", "dataset", "licence", "MIT"), rc2Actor, [2]string{i, g})
	s := dualStore()
	refused = deliverAll(s, w.lines)
	r := New(s)
	actors, err := identity.NewActors(w.lines)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := r.Statement(i)
	pa, _ := r.Statement(a)
	_, state, why = actors.Eligible(pa.St)
	return string(p.St.Status), p.St.Why, state, why, refused
}

// TestUnknownInceptionProfile pins how this reader treats an inception whose profile token it does not know,
// the behaviour a future profile (a new token on identity_inception) relies on: the inception is stored
// (not refused) and reads unsupported naming the profile, and an act under it reads unknown with
// unsupported_identity_profile, never eligible.
//
// Second row, today's behaviour and not a requirement of the profile: a fixed-root-v1 inception carrying an
// extra member reads valid and the act is eligible. This is deliberate in the design note: inception, grant
// and cut bodies accept unknown members (signed, part of the id, semantically inert), and anything a reader
// must honour to evaluate authority is introduced only behind a new crit token or a new profile token. So an
// extra plain member can never narrow or widen authority for a reader that predates it.
func TestUnknownInceptionProfile(t *testing.T) {
	t.Run("unknown profile token", func(t *testing.T) {
		status, why, state, reasons, refused := unknownProfileOutcome(t, "recoverable-root-v1", true)
		if refused != 0 {
			t.Fatalf("lines refused at delivery: %d (the inception must be stored)", refused)
		}
		if status != "unsupported" || !strings.Contains(why, "recoverable-root-v1") {
			t.Fatalf("inception status=%q note=%q; want unsupported naming the profile", status, why)
		}
		if state != policy.ActorUnknown {
			t.Fatalf("act state = %v, want unknown", state)
		}
		if !strings.Contains(strings.Join(reasons, " "), "unsupported_identity_profile") {
			t.Fatalf("act reasons = %v, want unsupported_identity_profile", reasons)
		}
	})
	t.Run("fixed-root-v1 with an extra member reads valid", func(t *testing.T) {
		status, _, state, reasons, refused := unknownProfileOutcome(t, wire.FixedRootProfile, true)
		if refused != 0 || status != "valid" || state != policy.ActorEligible || len(reasons) != 0 {
			t.Fatalf("refused=%d status=%q state=%v reasons=%v; want valid and eligible", refused, status, state, reasons)
		}
	})
}

// TestUnknownRootKind pins that an rc/2 line of a kind this reader does not know, on a fixed-root-v1 root log,
// reads "unknown kind" and makes the identity's earlier act unknown with unsupported_root_event: an
// authenticated in-lineage event the reader cannot understand stops the identity rather than being skipped.
func TestUnknownRootKind(t *testing.T) {
	w := newWorld(t)
	w.authored("K0", "K", "K0")
	i, g := w.identityOf("I", "IR", "K")
	a := w.signRC2("A", "K", "authored", obj("content", contentOf("Y"), "type", "dataset", "licence", "MIT"), rc2Actor, [2]string{i, g["K"]})
	h := w.signRC2("H", "IR", "identity_handover", obj("identity", i, "successor", w.signer("C")), rc2MarkerOnly, [2]string{})
	s := dualStore()
	if refused := deliverAll(s, w.lines); refused != 0 {
		t.Fatalf("refused %d", refused)
	}
	r := New(s)
	actors, err := identity.NewActors(w.lines)
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := r.Statement(h)
	pa, _ := r.Statement(a)
	_, state, why := actors.Eligible(pa.St)
	if string(ph.St.Status) != "unknown kind" || ph.St.Why != "identity_handover" {
		t.Fatalf("line status=%q why=%q; want unknown kind / identity_handover", ph.St.Status, ph.St.Why)
	}
	if state != policy.ActorUnknown || !strings.Contains(strings.Join(why, " "), "unsupported_root_event") {
		t.Fatalf("earlier act state=%v why=%v; want unknown with unsupported_root_event", state, why)
	}
}
