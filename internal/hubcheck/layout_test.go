package hubcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
)

// A response layout cited by a pinned profile (claims-model note §5.3.1a, "Response layouts"; §8).

var settlementLayout = canon.Encode(obj("layout", resolve.ResponseLayoutTag, "records", "/data", "state", "/settlementRunType"))

// layoutResponse is a settlement-shaped response whose records all carry run (synthetic data).
func layoutResponse(month, run string) []byte {
	return []byte(fmt.Sprintf(`{"data":[{"settlementDate":"%s-01","settlementPeriod":1,"settlementRunType":"%s","quantity":1.25},`+
		`{"settlementDate":"%s-01","settlementPeriod":2,"settlementRunType":"%s","quantity":-3}]}`, month, run, month, run))
}

// TestPinnedProfileLayoutAsHeld: C-core-104h through hub check. The base pins a profile citing a response layout in
// its documents, and holds the layout and every segment's response. Every segment asserts DF (final), but the held
// responses read R2 for April and May: the members' boundary is 2025-04-01 as held, so a declaration of 2025-06-01
// is refused on the bytes, and one of 2025-04-01 is could not check (as held). Control: the same series under the
// same profile without the layout cited: every asserted DF is final, so the members are final to the last window's
// end (2025-05-28) as captured, and the 2025-06-01 declaration is flagged on that, never as held.
func TestPinnedProfileLayoutAsHeld(t *testing.T) {
	conformance.Covers(t, "C-core-104h")
	ld := dig(settlementLayout)
	withLayout := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
		"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", []string{ld}))
	for _, cite := range []bool{true, false} {
		prof := settlementProfile
		if cite {
			prof = withLayout
		}
		pd := dig(prof)
		h := newHub(t, profilePolicy(pd))
		h.write(gate.BlobPath(pd), prof)
		h.write(gate.BlobPath(ld), settlementLayout)
		s := newSigner()
		g, segs := layoutSeries(h, s, pd)
		h.commit("series, segments, responses, the pinned profile and its layout")

		late := freeze(h, s, "late", g, segs, "2025-06-01")
		res, err := Check(h.dir, Config{Base: "main"})
		if err != nil {
			t.Fatal(err)
		}
		r := verdict(t, res, late)
		if !cite {
			// the asserted DF everywhere: final to the last window's end, as captured; never as held
			if !strings.Contains(r.Refusal.Detail, "members final to 2025-05-28 as captured, not re-checked") || strings.Contains(res.Render(), "as held") {
				t.Fatalf("control (no layout cited): %s\n%s", r.Verdict, res.Render())
			}
			continue
		}
		refusedAs(t, res, late, refusal.Policy, gate.HubRules+": series.refuse_premature_freeze")
		if res.Exit() != 1 || !r.Series.AsHeld || !strings.Contains(r.Refusal.Detail, "members final to 2025-04-01 as held (2 segments provisional)") ||
			!strings.Contains(r.Refusal.Detail, gate.AsHeldRefusal) {
			t.Fatalf("late: exit %d %v\n%s", res.Exit(), r.Refusal, res.Render())
		}
		at := freeze(h, s, "at", g, segs, "2025-04-01")
		res, err = Check(h.dir, Config{Base: "main"})
		if err != nil {
			t.Fatal(err)
		}
		r = verdict(t, res, at)
		if r.Verdict != gate.Undecided || res.Exit() != 3 || len(r.Labels) != 1 ||
			!strings.HasPrefix(r.Labels[0].Detail, "could not check (as held): frozen_before 2025-04-01 (declared) · members final to 2025-04-01 as held") ||
			!strings.Contains(r.Labels[0].Detail, gate.AsHeldUndecided) {
			t.Fatalf("at: %s exit %d %v\n%s", r.Verdict, res.Exit(), r.Labels, res.Render())
		}
	}
}

// layoutSeries writes five monthly segments citing src, each asserting DF, whose held responses read RF for Jan–Mar
// and R2 for Apr–May.
func layoutSeries(h *hub, s *signer, src string) (string, canon.Array) {
	gp, gline, g := s.sign("C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{s.key("C").Signer()}, "rule", obj("any_one", true)))
	h.write(gp, gline)
	segs := canon.Array{}
	for i := 0; i < 5; i++ {
		m := fmt.Sprintf("2025-%02d", i+1)
		run := "RF"
		if i >= 3 {
			run = "R2"
		}
		resp := layoutResponse(m, run)
		h.write(gate.BlobPath(dig(resp)), resp)
		ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", m), "response_digest", dig(resp),
			"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
		p, line, id := s.sign("O", "observed", obj("content", contentOf(resp), "class", "source", "referent", canon.Value(ref),
			"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted")),
			"finality", obj("rule", "run >= RF", "rule_source", src, "state_at_capture", obj("run", "DF"))))
		h.write(p, line)
		segs = append(segs, obj("statement", id, "role", "segment"))
	}
	return g, segs
}
