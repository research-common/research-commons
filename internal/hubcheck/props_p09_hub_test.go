package hubcheck

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/resolve"
)

// xzForbidden is `{"secret":1}` in xz: the forbidden key is inside it, invisible to a reader that treats it as
// opaque bytes.
var xzForbidden = func() []byte {
	b, _ := hex.DecodeString("fd377a585a0000016922de36020021011c00000010cf58cc01000b7b22736563726574223a317d008f9ca1410001200ca2ddb4bc9042990d010000000001595a")
	return b
}()

// TestSweepHubContentEvidenceNeverPasses: hub check builds its content reader from the tree (the base plus the
// change). A pushed statement carries intended_for outcome ok over a blob; with the rule dialect configured, the
// hub re-applies the named edition. When the blob is not in the tree, or is in a compression the scanner cannot
// read, the hub's own computation is `unchecked`, never `ok`; only the readable, compliant blob computes ok, and
// the readable forbidden one computes fail. The publisher's `ok` is shown as its word in every row.
func TestSweepHubContentEvidenceNeverPasses(t *testing.T) {
	rows := []struct {
		name  string
		blob  []byte // the content the statement names
		write bool   // whether the blob is in the change's tree
		want  resolve.Outcome
	}{
		{"missing: the blob is not in the tree", []byte(`{"reading":1}`), false, resolve.RuleUnchecked},
		{"unsupported: xz-compressed content", xzForbidden, true, resolve.RuleUnchecked},
		{"control: readable and compliant", []byte(`{"reading":1}`), true, resolve.RuleOK},
		{"control: readable and forbidden", []byte(`{"secret":"x"}`), true, resolve.RuleFail},
	}
	for _, row := range rows {
		h := newHub(t, defaultPolicy)
		s := newSigner()
		gp, gl, g := s.sign("C", "genesis", obj("type", "collection", "name", "r", "controllers", []string{s.key("C").Signer()}, "rule", obj("any_one", true)))
		e1b := editionBody(g, []string{g}, "rules", canon.Array{obj("dialect", "rc-test/1", "expr", "FORBID secret")})
		e1p, e1l, _ := s.sign("C", "edition", e1b)
		e1 := resolve.EditionID(e1b)
		h.write(gp, gl)
		h.write(e1p, e1l)
		h.commit("collection")
		h.branch("pr")
		fp, fl, _ := s.sign("M", "authored", obj("content", contentOf(row.blob), "type", "dataset",
			"intended_for", obj("resource", g, "edition", e1, "edition_applied", e1, "outcome", "ok")))
		h.write(fp, fl)
		if row.write {
			h.write(gate.BlobPath(dig(row.blob)), row.blob)
		}
		h.commit("statement")
		res := h.check("main", resolve.WithDialect(forbidDialect{}))
		r := verdict(t, res, fp)
		if r.Verdict != gate.Admitted || r.IntendedFor == nil {
			t.Errorf("%s: %s %v", row.name, r.Verdict, r.Refusal)
			continue
		}
		if r.IntendedFor.Named != row.want || r.IntendedFor.PublisherSaid != "ok" || r.IntendedFor.Endorsed {
			t.Errorf("%s: named %q (want %q), publisher %q, endorsed %v", row.name, r.IntendedFor.Named, row.want, r.IntendedFor.PublisherSaid, r.IntendedFor.Endorsed)
		}
		lab := ""
		for _, l := range r.Labels {
			if l.Token == gate.LabelIntendedFor {
				lab = l.Detail
			}
		}
		if !strings.Contains(lab, ": "+string(row.want)) || !strings.Contains(lab, "publisher says ok") {
			t.Errorf("%s: label %q", row.name, lab)
		}
	}
}

// TestSweepHubActorEvidenceNeverPasses: the actor evaluator behind hub check's `actor:` label. An act under
// a grant whose evidence is not in the tree, a key outside the grant and a cut grant are never labelled
// `eligible` (the exit stays 0: a label only). This extends TestActorLabels with the combinations that
// substitute evidence in one change: the act and a grant for a different identity, and a grant whose delegate
// inception is missing.
func TestSweepHubActorEvidenceNeverPasses(t *testing.T) {
	t.Run("grant signed by a key that is not the identity's root", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		// the grant is signed by a stranger key S, not the root R: it names the real identity but has no authority
		p, l := w.put("G", "S", "rc/2", "identity_grant", obj("identity", w.ids["I"],
			"delegate", obj("key", w.s.key("W").Signer(), "inception", w.ids["W.0"]),
			"permissions", canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", false)}))
		h.write(p, l)
		h.commit("base: a grant signed by a stranger")
		h.branch("act")
		a := w.act(h, "A", "W", "G")
		h.commit("an act under it")
		res := h.check("main")
		if got := actorOf(t, res, a); got.State == "eligible" {
			t.Fatalf("an act under a grant the root never signed is eligible: %v", got.Reasons)
		}
		if res.Exit() != 0 {
			t.Fatalf("a label changed the exit to %d", res.Exit())
		}
	})
	t.Run("grant delegates a key whose genesis is not the named inception", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		p, l := w.put("G", "R", "rc/2", "identity_grant", obj("identity", w.ids["I"],
			"delegate", obj("key", w.s.key("W").Signer(), "inception", strings.Repeat("d", 64)),
			"permissions", canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", false)}))
		h.write(p, l)
		h.commit("base: a grant naming an inception nobody holds")
		h.branch("act")
		a := w.act(h, "A", "W", "G")
		h.commit("an act")
		res := h.check("main")
		if got := actorOf(t, res, a); got.State == "eligible" {
			t.Fatalf("an act under a grant whose delegate inception is not the key's genesis is eligible: %v", got.Reasons)
		}
	})
}
