package hubcheck

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/gate"
)

// P-09 over push's own delegated checks (the preconditions a sender checks before transport): the withheld-bytes
// precondition (is there a serving `holds`?) and the anchor-required precondition (does an anchors line cover the
// statement?). Each check is handed evidence that is missing, of the wrong kind or lying about what it covers,
// and the push is refused (nothing transported) every time; the control rows are the only ones that pass.

func pushWorld(t *testing.T) (*hub, *signer) {
	h := newHub(t, defaultPolicy)
	withRemote(h)
	return h, newSigner()
}

func preconditions(t *testing.T, h *hub) *Preconditions {
	t.Helper()
	pl := plan(t, h, PushConfig{})
	return pl.CheckPreconditions("")
}

var withheldAvail = obj("redistribution", "withheld", "obtainable", false, "withheld_until", "edition 2")

// TestSweepPushWithheldNeverPasses: the blob a statement declares withheld is carried only when a serving, current
// `holds` for exactly that digest is in the history. A holds for another digest, a withdrawn holds, and a
// holds that a later withdrawal of the same key cancelled each leave the blob refused; so does a declaration made
// by an `observed`. Control: a current holds releases the blob.
func TestSweepPushWithheldNeverPasses(t *testing.T) {
	secret := []byte("withheld pool nonce 9f8e7d")
	other := []byte("a different blob")
	type row struct {
		name   string
		build  func(h *hub, s *signer)
		refuse bool
	}
	declare := func(h *hub, s *signer) {
		p, l, _ := s.sign("A", "authored", obj("content", contentOf(secret), "type", "dataset", "availability", withheldAvail))
		h.write(p, l)
	}
	holds := func(h *hub, s *signer, n string, b []byte, extra ...any) {
		p, l, _ := s.sign(n, "holds", obj(append([]any{"content", contentOf(b)}, extra...)...))
		h.write(p, l)
	}
	rows := []row{
		{"missing: no holds at all", func(h *hub, s *signer) { declare(h, s) }, true},
		{"wrong: a holds for another digest", func(h *hub, s *signer) { declare(h, s); holds(h, s, "H", other) }, true},
		{"wrong: a withdrawn holds", func(h *hub, s *signer) { declare(h, s); holds(h, s, "H", secret, "withdrawn", true) }, true},
		{"lying: a holds the same key then withdrew", func(h *hub, s *signer) {
			declare(h, s)
			holds(h, s, "H", secret)
			holds(h, s, "H", secret, "withdrawn", true)
		}, true},
		{"declared by an observed", func(h *hub, s *signer) {
			p, l, _ := s.sign("A", "observed", obj("content", contentOf(secret), "class", "none-yet", "referent", canon.Value(obj()),
				"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted")), "availability", withheldAvail))
			h.write(p, l)
		}, true},
		{"control: a current holds releases it", func(h *hub, s *signer) { declare(h, s); holds(h, s, "H", secret) }, false},
		{"control: holds, withdrawn, held again", func(h *hub, s *signer) {
			declare(h, s)
			holds(h, s, "H", secret)
			holds(h, s, "H", secret, "withdrawn", true)
			holds(h, s, "H", secret)
		}, false},
	}
	for _, r := range rows {
		h, s := pushWorld(t)
		r.build(h, s)
		h.write(gate.BlobPath(dig(secret)), secret)
		h.commit(r.name)
		pre := preconditions(t, h)
		carried := len(pre.Withheld) == 0
		if r.refuse && (carried || !pre.Refused()) {
			t.Errorf("%s: the withheld blob would be carried (withheld rows %v)", r.name, pre.Withheld)
		}
		if !r.refuse && (!carried || len(pre.Withheld) != 0) {
			t.Errorf("%s: control refused: %v", r.name, pre.Withheld)
		}
		if r.refuse && (len(pre.Withheld) != 1 || pre.Withheld[0].Digest != dig(secret) || len(pre.Withheld[0].By) != 1) {
			t.Errorf("%s: row %+v", r.name, pre.Withheld)
		}
	}
}

// TestSweepPushAnchorNeverPasses: a statement whose default is `anchor required` is carried only when an anchors
// line of its own key covers it (the line after it in that key's log). An anchors line by another key, one that
// covers an earlier head, and one naming a head nobody holds do not cover it. Every refusing row is Refused() and
// lists no covering line. Control: the key's own later line covers it.
func TestSweepPushAnchorNeverPasses(t *testing.T) {
	proof := dig([]byte("proof"))
	anch := func(s *signer, n, covered string) (string, []byte) {
		p, l, _ := s.sign(n, "anchors", obj("covered", covered, "proof", proof, "proof_format", "ots-detached-v1"))
		return p, l
	}
	type row struct {
		name  string
		build func(h *hub, s *signer) (target string)
		cover bool
	}
	rows := []row{
		{"missing: no anchors line", func(h *hub, s *signer) string {
			p, l, id := s.sign("A", "authored", obj("content", contentOf([]byte("a")), "type", "dataset"))
			h.write(p, l)
			return id
		}, false},
		{"wrong: another key's anchors line over this id", func(h *hub, s *signer) string {
			p, l, id := s.sign("A", "authored", obj("content", contentOf([]byte("a")), "type", "dataset"))
			h.write(p, l)
			ap, al := anch(s, "B", id)
			h.write(ap, al)
			return id
		}, false},
		{"lying: an anchors line over an earlier head", func(h *hub, s *signer) string {
			g, gl, gid := s.sign("A", "authored", obj("content", contentOf([]byte("first")), "type", "dataset", "provenance", obj()))
			h.write(g, gl)
			ap, al := anch(s, "A", gid) // covers only the first
			h.write(ap, al)
			p, l, id := s.sign("A", "authored", obj("content", contentOf([]byte("second")), "type", "dataset"))
			h.write(p, l)
			return id
		}, false},
		{"lying: an anchors line naming a head nobody holds", func(h *hub, s *signer) string {
			p, l, id := s.sign("A", "authored", obj("content", contentOf([]byte("a")), "type", "dataset"))
			h.write(p, l)
			ap, al := anch(s, "A", strings.Repeat("c", 64))
			h.write(ap, al)
			return id
		}, false},
		{"control: the key's own later anchors line", func(h *hub, s *signer) string {
			p, l, id := s.sign("A", "authored", obj("content", contentOf([]byte("a")), "type", "dataset"))
			h.write(p, l)
			ap, al := anch(s, "A", id)
			h.write(ap, al)
			return id
		}, true},
	}
	for _, r := range rows {
		h, s := pushWorld(t)
		target := r.build(h, s)
		h.commit(r.name)
		pre := preconditions(t, h)
		var row *AnchorRow
		for i := range pre.Anchors {
			if pre.Anchors[i].ID == target {
				row = &pre.Anchors[i]
			}
		}
		if row == nil {
			t.Errorf("%s: the target statement is not among the carried rows", r.name)
			continue
		}
		if row.Standing != btctime.AnchorRequired {
			t.Errorf("%s: standing %q, want anchor required (the fixture drifted)", r.name, row.Standing)
			continue
		}
		if r.cover && (row.Refused || len(row.CoveredBy) != 1) {
			t.Errorf("%s: control refused or uncovered: %+v", r.name, row)
		}
		if !r.cover && (!row.Refused || len(row.CoveredBy) != 0 || !pre.Refused()) {
			t.Errorf("%s: carried without a covering line: %+v", r.name, row)
		}
	}
}
