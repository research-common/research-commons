package hubcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/reqlog"
	"github.com/research-common/research-commons/internal/resolve"
)

const batchSeriesEP = "https://api.example/v1/settlements"

// batchLayoutSeries writes five monthly segments citing src, each a batch source capture asserting DF whose content
// is an archive of its request log and two responses: both read RF for Jan–Mar; for Apr–May the second reads R2.
// dropFrom names a month (1-based, 0 for none) whose archive leaves out its second logged response.
func batchLayoutSeries(t *testing.T, h *hub, s *signer, src string, dropFrom int) (string, canon.Array) {
	gp, gline, g := s.sign("C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{s.key("C").Signer()}, "rule", obj("any_one", true)))
	h.write(gp, gline)
	segs := canon.Array{}
	for i := 0; i < 5; i++ {
		m := fmt.Sprintf("2025-%02d", i+1)
		second := "RF"
		if i >= 3 {
			second = "R2"
		}
		resps := [][]byte{layoutResponse(m, "RF"), layoutResponse(m, second)}
		var es []reqlog.Entry
		files := [][2]string{{"requests.jsonl", ""}}
		for j, r := range resps {
			es = append(es, reqlog.Entry{Endpoint: batchSeriesEP, Parameters: obj("period", m, "part", fmt.Sprint(j+1)), Status: 200,
				Time: fmt.Sprintf("2026-01-02T00:00:0%dZ", j), ResponseDigest: dig(r)})
			if !(dropFrom == i+1 && j == 1) {
				files = append(files, [2]string{fmt.Sprintf("r%d.json", j+1), string(r)})
			}
		}
		log := reqlog.Encode(es)
		files[0][1] = string(log)
		archive := gzTar(t, files...)
		h.write(gate.BlobPath(dig(archive)), archive)
		ref := obj("requests", obj("digest", dig(log), "format", reqlog.Format, "count", len(resps), "endpoint", batchSeriesEP),
			"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
		p, line, id := s.sign("O", "observed", obj("content", contentOf(archive), "class", "source", "referent", canon.Value(ref),
			"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted")),
			"finality", obj("rule", "run >= RF", "rule_source", src, "state_at_capture", obj("run", "DF"))))
		h.write(p, line)
		segs = append(segs, obj("statement", id, "role", "segment"))
	}
	return g, segs
}

// TestPinnedProfileBatchSegmentsAsHeld: C-core-104h, the batch variant, through hub check. As
// TestPinnedProfileLayoutAsHeld, but every segment is a batch capture whose archive carries its request log and
// responses: each segment reads at its least logged response through its log, so the members' boundary is 2025-04-01
// as held and a 2025-06-01 declaration is refused on the bytes; 2025-04-01 is could not check (as held). Variant: one
// segment's archive lacks a logged response (its log check fails): that segment's asserted DF is used and the
// boundary is the weaker `as captured, not re-checked`. Control: the profile without the layout, never as held.
func TestPinnedProfileBatchSegmentsAsHeld(t *testing.T) {
	conformance.Covers(t, "C-core-104h")
	ld := dig(settlementLayout)
	withLayout := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
		"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", []string{ld}))
	for _, c := range []struct {
		name string
		cite bool
		drop int
	}{{"held", true, 0}, {"one log fails", true, 4}, {"control", false, 0}} {
		t.Run(c.name, func(t *testing.T) {
			prof := settlementProfile
			if c.cite {
				prof = withLayout
			}
			pd := dig(prof)
			h := newHub(t, profilePolicy(pd))
			h.write(gate.BlobPath(pd), prof)
			h.write(gate.BlobPath(ld), settlementLayout)
			s := newSigner()
			g, segs := batchLayoutSeries(t, h, s, pd, c.drop)
			h.commit("batch series, the pinned profile and its layout")

			late := freeze(h, s, "late", g, segs, "2025-06-01")
			res, err := Check(h.dir, Config{Base: "main"})
			if err != nil {
				t.Fatal(err)
			}
			r := verdict(t, res, late)
			refusedAs(t, res, late, refusal.Policy, gate.HubRules+": series.refuse_premature_freeze")
			switch c.name {
			case "control":
				if !strings.Contains(r.Refusal.Detail, "members final to 2025-05-28 as captured, not re-checked") || strings.Contains(res.Render(), "as held") {
					t.Fatalf("control: %v\n%s", r.Refusal, res.Render())
				}
				return
			case "one log fails":
				// April's second response is missing, so April reads at its asserted DF; May's R2 still read from bytes
				if r.Series.AsHeld || !strings.Contains(r.Refusal.Detail, "members final to 2025-05-01 as captured, not re-checked (1 segment provisional)") ||
					!strings.Contains(r.Refusal.Detail, gate.AsCapturedRefusal) {
					t.Fatalf("gap: %v\n%s", r.Refusal, r.Series.Render())
				}
				if !strings.Contains(r.Series.Render(), "from 2025-04-01: final (as captured, not re-checked)") ||
					!strings.Contains(r.Series.Render(), "from 2025-05-01: provisional (as held)") {
					t.Fatalf("gap segments:\n%s", r.Series.Render())
				}
				return
			}
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
				!strings.HasPrefix(r.Labels[0].Detail, "could not check (as held): frozen_before 2025-04-01 (declared) · members final to 2025-04-01 as held") {
				t.Fatalf("at: %s exit %d %v\n%s", r.Verdict, res.Exit(), r.Labels, res.Render())
			}
		})
	}
}
