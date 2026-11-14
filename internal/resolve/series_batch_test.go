package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
)

// Series segments that are batch captures (claims-model note §5.3.1a, "a batch reads at its least response"; §8).
// Fixtures are synthetic settlement-shaped responses, never real data.

// batchSeriesWorld is a reader holding profile P (SF < R1 < R2 < RF < DF), citing layout L when cite is true, and a
// series of three monthly segments (Jan, Feb, Mar), each a batch source capture `run >= RF` citing P and asserting
// DF, whose content is an archive of its request log and responses.
type batchSeriesWorld struct {
	w       *world
	g       string
	p       *SourceProfile
	blobs   map[string][]byte
	content tableContent
	segs    []string
	fs      []*batchFixture
}

func newBatchSeriesWorld(t *testing.T, cite bool, months [][][]byte) *batchSeriesWorld {
	t.Helper()
	bw := &batchSeriesWorld{w: newWorld(t), blobs: map[string][]byte{}, content: tableContent{}}
	lay := layoutBytes("/data", "/settlementRunType")
	l := mustLayout(t, lay)
	bw.blobs[l.Digest] = lay
	docs := []string{timetable}
	if cite {
		docs = append(docs, l.Digest)
	}
	bw.p = mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
		"labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", docs)))
	bw.p.AttachLayouts(func(d string) ([]byte, error) { return bw.blobs[d], nil })
	bw.g = bw.w.sign("G", "A", "genesis", obj("type", "series", "name", "settlements", "controllers", bw.w.controllers("A"), "rule", obj("any_one", true)))
	for i, resps := range months {
		m := "2025-0" + itoa(i+1)
		f := &batchFixture{content: dig("batch-archive-" + m)}
		var es []reqlog.Entry
		for j, r := range resps {
			f.responses = append(f.responses, r)
			es = append(es, reqlog.Entry{Endpoint: batchEP, Parameters: obj("period", itoa(j+1)), Status: 200,
				Time: "2026-10-16T05:00:0" + itoa(j) + "Z", ResponseDigest: sha(r)})
		}
		f.log = reqlog.Encode(es)
		bw.fs = append(bw.fs, f)
		bw.content[f.content] = f.units()
		bw.segs = append(bw.segs, bw.w.sign("S"+m, "O", "observed", obj("content", obj("digest", f.content, "size", 1), "class", "source",
			"referent", obj("requests", batchReq(f, len(resps), "endpoint", batchEP), "window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z")),
			"capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted"), "finality", profileRun(bw.p.Digest, "DF"))))
	}
	bw.w.editionWith("E", "A", bw.g, []string{bw.g}, "members", segs(bw.segs...), "frozen_before", obj("date", "2025-03-01"))
	return bw
}

func (bw *batchSeriesWorld) rules() ProfileRules {
	return NewProfileRules(bw.p).WithBytes(func(d string, max int64) ([]byte, string) {
		b, ok := bw.blobs[d]
		if !ok {
			return nil, "not held"
		}
		return b, ""
	}, 0)
}

// series resolves the series under every sampled delivery order (one rendering required) with the given options
// beside ProfileSegments over the world's rules.
func (bw *batchSeriesWorld) series(t *testing.T, opts ...Option) *Series {
	t.Helper()
	opts = append([]Option{WithSegments(ProfileSegments{Rules: bw.rules()})}, opts...)
	var first string
	var out *Series
	for _, o := range append([][]int{nil}, sampleOrders(len(bw.w.lines), uint64(len(bw.w.lines))*17, 6)...) {
		s, ok := bw.w.store(o, opts...).Series(bw.g, "")
		if !ok {
			t.Fatal("series not found")
		}
		r := s.Render()
		for _, g := range s.Segments {
			if g.Layout != nil {
				r += "\n" + g.Member + " " + g.Layout.String()
			}
		}
		if first == "" {
			first, out = r, s
		} else if r != first {
			t.Fatalf("order %v changed the series view:\n%s\nvs\n%s", o, r, first)
		}
	}
	return out
}

// segmentOf is the series segment for statement id.
func segmentOf(t *testing.T, s *Series, id string) Segment {
	t.Helper()
	for _, g := range s.Segments {
		if g.Member == id {
			return g
		}
	}
	t.Fatalf("segment %s not in the series", id)
	return Segment{}
}

// TestSeriesBatchSegmentsAsHeld: C-core-104h, the batch variant, in the resolver. Every segment is a batch capture
// asserting DF; its responses read RF (Jan), R2 at least (Feb) and RF (Mar). With a content reader the resolver
// locates each segment's request log, so each segment reads at its least logged response, exactly the read the
// observation view gives the same statement for the same held set (asserted equal, layout line and state), and the
// boundary is `as held` at 2025-02-01. Gaps: one segment's archive lacks a logged response (log `fail`), or the
// content is not held at all: that segment's layout read is unchecked with the observation view's own why, its
// asserted DF is used, and the boundary is the weaker `as captured, not re-checked`. Without a content reader (the
// record alone) the batch read keeps its record-only why. Control: P without L, every asserted DF final, never held.
func TestSeriesBatchSegmentsAsHeld(t *testing.T) {
	conformance.Partial(t, "C-core-104h", "batch variant, resolver half; through hub check and pull in their packages")
	months := [][][]byte{
		{batchRun(1, "RF", "RF"), batchRun(2, "RF", "DF")},
		{batchRun(1, "RF"), batchRun(2, "R2", "RF"), batchRun(3, "DF")},
		{batchRun(1, "RF"), batchRun(2, "DF")},
	}
	bw := newBatchSeriesWorld(t, true, months)
	s := bw.series(t, WithContent(bw.content))
	has(t, s.Line(), "frozen_before 2025-03-01 (declared) · members final to 2025-02-01 as held (1 segment provisional) · FLAGGED: declared later than computed")
	if !s.AsHeld {
		t.Fatalf("not as held:\n%s", s.Render())
	}
	// the same read as the observation view, statement by statement, for the same held set
	for i, id := range bw.segs {
		g := segmentOf(t, s, id)
		o := obsView(t, bw.w, id, WithFinalityRules(bw.rules()), WithObservedContent(bw.content))
		if g.Layout == nil || o.Layout == nil || g.Layout.String() != o.Layout.String() {
			t.Fatalf("segment %d: series read %v, observation read %v", i, g.Layout, o.Layout)
		}
		want := map[bool]string{true: "final", false: "provisional"}[i != 1]
		if g.Final != want || !g.Held || !g.AsCaptured {
			t.Fatalf("segment %d: %+v", i, g.SegmentState)
		}
	}
	has(t, segmentOf(t, s, bw.segs[1]).Layout.String(), "state R2 read from the 3 held responses (records at R2..DF across 3 responses, read as R2)")

	// a gap in one segment: the archive lacks Feb's second logged response (the log check fails)
	us := bw.fs[1].units()
	gap := tableContent{}
	for k, v := range bw.content {
		gap[k] = v
	}
	gap[bw.fs[1].content] = append(us[:2:2], us[3:]...)
	s = bw.series(t, WithContent(gap))
	g := segmentOf(t, s, bw.segs[1])
	o := obsView(t, bw.w, bw.segs[1], WithFinalityRules(bw.rules()), WithObservedContent(gap))
	if g.Layout == nil || g.Layout.State != "" || g.Layout.String() != o.Layout.String() || g.Final != "final" || g.Held {
		t.Fatalf("gap: series %+v %v, observation %v", g.SegmentState, g.Layout, o.Layout)
	}
	has(t, g.Layout.String(), "unchecked (request log fail (entry 2, endpoint "+batchEP+": response")
	has(t, g.Layout.String(), "no response is read")
	has(t, s.Line(), "members final to 2025-03-28 as captured, not re-checked")
	hasNot(t, s.Line(), "as held")
	has(t, s.Render(), "from 2025-02-01: final (as captured, not re-checked)")
	has(t, s.Render(), "from 2025-01-01: final (as held)")

	// content not held: the log is unchecked, so is every segment's read; asserted DF everywhere
	s = bw.series(t, WithContent(tableContent{}))
	for _, id := range bw.segs {
		g := segmentOf(t, s, id)
		if g.Layout == nil || !strings.Contains(g.Layout.String(), "unchecked (request log unchecked (content not held): no response is read)") || g.Held {
			t.Fatalf("no content: %+v %v", g.SegmentState, g.Layout)
		}
	}
	has(t, s.Line(), "members final to 2025-03-28 as captured, not re-checked")

	// no content reader at all (the record alone): no read is faked; the record-only why stays
	s = bw.series(t)
	for _, id := range bw.segs {
		g := segmentOf(t, s, id)
		if g.Layout == nil || g.Layout.Why != "a batch capture: its responses are read through its request log, which this read does not check" || g.Held {
			t.Fatalf("no reader: %+v %v", g.SegmentState, g.Layout)
		}
	}
	has(t, s.Line(), "members final to 2025-03-28 as captured, not re-checked")

	// control: P without L, the same content: every asserted DF is final, as captured, never as held
	ctl := newBatchSeriesWorld(t, false, months)
	s = ctl.series(t, WithContent(ctl.content))
	has(t, s.Line(), "members final to 2025-03-28 as captured, not re-checked")
	hasNot(t, s.Render(), "as held")
}

// TestSeriesBatchSegmentReadsLikeObservation: the batch segment read is the non-segment batch read for the same held
// set, whatever the responses' log order, and an all-final batch reads final as held at its least. Seeded over
// response sets drawn from the profile's labels.
func TestSeriesBatchSegmentReadsLikeObservation(t *testing.T) {
	labels := []string{"SF", "R1", "R2", "RF", "DF"}
	seed := uint64(0x5e6ba7c4)
	next := func(n int) int {
		seed = seed*6364136223846793005 + 1442695040888963407
		return int((seed >> 33) % uint64(n))
	}
	for round := 0; round < 12; round++ {
		var months [][][]byte
		for m := 0; m < 3; m++ {
			var rs [][]byte
			for k := 0; k < 1+next(3); k++ {
				var runs []string
				for j := 0; j < 1+next(3); j++ {
					runs = append(runs, labels[next(len(labels))])
				}
				rs = append(rs, batchRun(k+1, runs...))
			}
			months = append(months, rs)
		}
		bw := newBatchSeriesWorld(t, true, months)
		s := bw.series(t, WithContent(bw.content))
		for i, id := range bw.segs {
			g := segmentOf(t, s, id)
			o := obsView(t, bw.w, id, WithFinalityRules(bw.rules()), WithObservedContent(bw.content))
			if g.Layout == nil || o.Layout == nil || g.Layout.String() != o.Layout.String() || !g.Held {
				t.Fatalf("round %d segment %d: series %v, observation %v", round, i, g.Layout, o.Layout)
			}
			// the observation view's referent status and the segment's state agree on final vs provisional
			if (g.Final == "final") != (o.ReferentStatus == RefFinalHeld) {
				t.Fatalf("round %d segment %d: segment %s, observation %s", round, i, g.Final, o.ReferentStatus)
			}
		}
		// reversed log order within every batch: the same states
		var rev [][][]byte
		for _, rs := range months {
			r := append([][]byte(nil), rs...)
			for a, b := 0, len(r)-1; a < b; a, b = a+1, b-1 {
				r[a], r[b] = r[b], r[a]
			}
			rev = append(rev, r)
		}
		bw2 := newBatchSeriesWorld(t, true, rev)
		s2 := bw2.series(t, WithContent(bw2.content))
		if s.Line() != s2.Line() {
			t.Fatalf("round %d: log order changed the boundary: %s vs %s", round, s.Line(), s2.Line())
		}
		for i := range bw.segs {
			a, b := segmentOf(t, s, bw.segs[i]), segmentOf(t, s2, bw2.segs[i])
			if a.Final != b.Final || a.Layout.State != b.Layout.State {
				t.Fatalf("round %d segment %d: %s/%s vs %s/%s", round, i, a.Final, a.Layout.State, b.Final, b.Layout.State)
			}
		}
	}
}
