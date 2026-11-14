package resolve

import (
	"fmt"
	"strings"
	"testing"
)

// seriesRenderGolden is the rendering of seriesWorld's edition captured before a segment's layout read was shown
// (with the renderer of the previous release): segments without a layout read render exactly as they always did.
const seriesRenderGolden = `series cc1702d128fd at 2d30458eebb1
  frozen_before 2025-06-01 (declared) · members final to 2025-04-01 (2 segments provisional) · FLAGGED: declared later than computed
  segment 6760f9c1ecc0 from 2025-01-01: final
  segment 14f91e45f1f4 from 2025-02-01: final
  segment df0f47ae3241 from 2025-03-01: final
  segment 98c4abda7fc0 from 2025-04-01: provisional
  segment bf709662fc1a from 2025-05-01: provisional
  declared boundary is later than the members' finality boundary
`

func seriesRenderOf(t *testing.T) string {
	t.Helper()
	w, g, ids, f := seriesWorld(t)
	w.editionWith("E1", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-06-01"))
	s, ok := w.store(nil, WithSegments(f)).Series(g, "")
	if !ok {
		t.Fatal("no series view")
	}
	for _, g := range s.Segments {
		if g.Layout != nil {
			t.Fatal("the fixture has a layout read: it no longer pins the layout-free rendering")
		}
	}
	return s.Render()
}

func TestSeriesRenderWithoutLayoutUnchanged(t *testing.T) {
	got := seriesRenderOf(t)
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		if strings.Contains(line, "response layout") {
			t.Fatalf("a segment without a layout read gained a line: %q", line)
		}
	}
	want := seriesRenderGolden
	if got != want {
		t.Fatalf("rendering changed:\n%s\nwant\n%s", got, want)
	}
}

// TestSeriesRenderShowsSegmentLayoutRead: a batch segment whose layout read exists gets one indented line under
// it, the observation view's own words (spread, least, or unchecked with its why); the segment lines themselves
// are unchanged, and a segment without a read adds nothing.
func TestSeriesRenderShowsSegmentLayoutRead(t *testing.T) {
	months := [][][]byte{
		{batchRun(1, "RF", "RF"), batchRun(2, "RF", "DF")},
		{batchRun(1, "RF"), batchRun(2, "R2", "RF"), batchRun(3, "DF")},
		{batchRun(1, "RF"), batchRun(2, "DF")},
	}
	bw := newBatchSeriesWorld(t, true, months)
	s := bw.series(t, WithContent(bw.content))
	out := s.Render()
	for i, id := range bw.segs {
		g := segmentOf(t, s, id)
		if g.Layout == nil {
			t.Fatalf("segment %d has no layout read", i)
		}
		head := fmt.Sprintf("  segment %s from %s: ", shortMember(id), g.From)
		line := "    " + g.Layout.String() + "\n"
		at := strings.Index(out, head)
		if at < 0 {
			t.Fatalf("segment %d line missing:\n%s", i, out)
		}
		rest := out[at:]
		rest = rest[strings.Index(rest, "\n")+1:]
		if !strings.HasPrefix(rest, line) {
			t.Fatalf("segment %d: the layout read is not the indented line under it:\n%s", i, out)
		}
	}
	has(t, out, "    response layout")
	has(t, out, "state R2 read from the 3 held responses (records at R2..DF across 3 responses, read as R2)")

	// a gap: the read is unchecked and says why under that segment
	us := bw.fs[1].units()
	gap := tableContent{}
	for k, v := range bw.content {
		gap[k] = v
	}
	gap[bw.fs[1].content] = append(us[:2:2], us[3:]...)
	out = bw.series(t, WithContent(gap)).Render()
	has(t, out, "    response layout")
	has(t, out, "unchecked (request log fail")

	// the control (P without L): no layout is read for any segment, so no line is added
	ctl := newBatchSeriesWorld(t, false, months)
	cs := ctl.series(t, WithContent(ctl.content))
	for _, g := range cs.Segments {
		if g.Layout != nil && g.Layout.Layout != "" {
			t.Fatalf("control has a layout %q", g.Layout.Layout)
		}
	}
	for _, line := range strings.Split(cs.Render(), "\n") {
		if strings.HasPrefix(line, "    response layout") && !strings.Contains(line, "unchecked") {
			t.Fatalf("control read a layout: %q", line)
		}
	}
}
