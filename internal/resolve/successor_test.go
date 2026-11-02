package resolve

import (
	"strings"
	"testing"
)

// TestSuccessorInheritsNothing: claims §4.1. A successor named by a rotation inherits no
// claims: the predecessor's `authored` stay the predecessor's. When a later or contesting claimant is the
// successor named by another claimant's rotation that counts, explain names it and says a reader may follow it
// by reader-policy selection. The hint is display only: authorship state, defaults, grade and verify exit are
// identical to the same world without the rotation. Control: a rotation that counts toward nothing (cut by a
// hard revocation whose last_good precedes it) gives no hint.
func TestSuccessorInheritsNothing(t *testing.T) {
	const hint = "is the successor named by claimant "
	type result struct {
		outcome, grade string
		exit           int
		explain        string
	}
	build := func(rotate, anchored, cut bool) result {
		w := newWorld(t)
		a1 := w.authored("A1", "A", "X", "licence", "CC0-1.0")
		if anchored {
			w.anchor("AA", "A", "btc:100")
		}
		if rotate {
			w.sign("ROT", "A", "rotate_key", obj("successor", w.signer("A2")))
		}
		if cut {
			w.sign("REV", "A", "revoke_key", obj("reason", "key_compromise", "last_good", a1))
		}
		w.authored("S1", "A2", "X", "licence", "CC-BY-4.0")
		if anchored {
			w.anchor("SA", "A2", "btc:150")
		}
		r := w.store(nil, WithTimeVerifier(newFakeBitcoin(100, 150)))
		if rotate {
			// the rotation counts in the hint worlds and counts toward nothing in the control
			if p, ok := r.Statement(w.ids["ROT"]); !ok || p.Counts() == cut || len(r.logs.Successions()) != 1 {
				t.Fatalf("fixture: rotation counts=%v (cut=%v), successions %v", ok && p.Counts(), cut, r.logs.Successions())
			}
		}
		a := r.Artifact(dig("X"))
		code, _ := a.VerifyExit()
		return result{a.Outcome(), a.Grade.Tier + "|" + a.Grade.Why, code, strings.Join(a.Explain, "\n")}
	}
	for _, anchored := range []bool{true, false} {
		name := map[bool]string{true: "priority (successor is the later claimant)", false: "contested"}[anchored]
		with, without := build(true, anchored, false), build(false, anchored, false)
		if !strings.Contains(with.explain, hint) || !strings.Contains(with.explain, "a successor inherits no claims") ||
			!strings.Contains(with.explain, "reader-policy selection") {
			t.Fatalf("%s: no successor hint in explain:\n%s", name, with.explain)
		}
		if strings.Contains(without.explain, hint) {
			t.Fatalf("%s: a hint without any rotation:\n%s", name, without.explain)
		}
		if with.outcome != without.outcome || with.grade != without.grade || with.exit != without.exit {
			t.Fatalf("%s: the hint world moved the answer: %+v vs %+v", name, with, without)
		}
		if anchored && !strings.HasPrefix(with.outcome, string(Priority)) || !anchored && !strings.HasPrefix(with.outcome, string(ContestedAuthorship)) {
			t.Fatalf("%s: fixture outcome %s", name, with.outcome)
		}
		// the predecessor keeps its claim: the successor's licence is a rival, never the predecessor's default
		if anchored && !strings.Contains(with.outcome, `licence="CC0-1.0"`) {
			t.Fatalf("%s: the predecessor's declaration moved: %s", name, with.outcome)
		}
		// control: the same rotation cut by a hard revocation counts toward nothing, so no hint
		if ctl := build(true, anchored, true); strings.Contains(ctl.explain, hint) {
			t.Fatalf("%s: a rotation that does not count gave a hint:\n%s", name, ctl.explain)
		}
	}
}
