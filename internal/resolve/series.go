package resolve

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
)

// Growing series (claims-model note §8 "Growing series", §7 "Declared beside computed"; wire-format note §5
// `frozen_before`; C-core-101 – C-core-104).
//
// A segment is a member with role `segment` (wire-format note §12, "Segments are members"). The edition's
// `frozen_before` is the controller's declaration; the reader computes the members' finality boundary from
// the segments' own finality rules and shows both, never one in place of the other:
//
//   frozen_before 2025-06-01 (declared) · members final to 2025-04-01 (2 segments provisional)
//
// The computed boundary is the position of the earliest segment that is not final (every segment before it
// is final), or the end of the last segment when all are. It is `unchecked` when a segment carries no
// finality rule (C-core-102) or its state cannot be re-checked; `not comparable` when the declared unit
// differs from the computed one (never converted). A declared boundary later than the computed one is
// flagged. Nothing derives a boundary from the other.
//
// Where a segment sits (its position in the boundary's unit) and whether its rule now holds are the reader's
// re-check of the source, so they come from a SegmentReader the reader configures. The default reads the
// position from the segment's referent window (or `at`) as a date and re-checks no finality.
//
// An edition that replaces a segment positioned before its predecessor's `frozen_before` (a segment of the
// predecessor dropped, or one added, below the boundary) is shown `REVISED-FROZEN`. Both editions stay
// resolvable (I3); nothing is removed.

// RevisedFrozen is the display token for an edition that rewrites a segment below its predecessor's
// declared `frozen_before` (§13).
const RevisedFrozen = "REVISED-FROZEN"

// Boundary is a position in one of the finality units: a date, a block height, or a run label.
type Boundary struct {
	Unit   string // "date", "height", "run"; "" when absent
	Date   string
	Height int64
	Run    string
}

func (b Boundary) String() string {
	switch b.Unit {
	case "date":
		return b.Date
	case "height":
		return "height " + strconv.FormatInt(b.Height, 10)
	case "run":
		return "run " + b.Run
	}
	return "none"
}

// compare orders two boundaries of one unit. ok is false across units, and for runs: run labels carry no
// order the core defines (see the spec finding in the slice report), so two runs compare only as equal.
func (b Boundary) compare(o Boundary) (int, bool) {
	if b.Unit != o.Unit || b.Unit == "" {
		return 0, false
	}
	switch b.Unit {
	case "date":
		return strings.Compare(b.Date, o.Date), true
	case "height":
		return int(b.Height - o.Height), true
	}
	if b.Run == o.Run {
		return 0, true
	}
	return 0, false
}

// SegmentState is what the reader's re-check knows about one segment.
type SegmentState struct {
	// From and To bound the segment in its unit; To is the zero Boundary when unknown.
	From, To Boundary
	// Rule is false when the segment carries no finality rule.
	Rule bool
	// Final is the re-checked state: "final", "provisional", or "unchecked" (with Why).
	Final string
	Why   string
}

// SegmentReader is the reader's re-check of a segment's position and finality.
type SegmentReader interface {
	Segment(m *Member) SegmentState
}

// WithSegments sets the reader's segment re-check.
func WithSegments(s SegmentReader) Option { return func(r *Resolver) { r.rules.segments = s } }

// RecordSegments is the default SegmentReader: the position is the date of referent.window.from (to
// referent.window.to), or of referent.at; finality is not re-checked.
type RecordSegments struct{}

// Segment implements SegmentReader.
func (RecordSegments) Segment(m *Member) SegmentState {
	s := SegmentState{Final: "unchecked", Why: "finality not re-checked by this reader"}
	if m.record == nil {
		s.Why = m.recordWhy
		return s
	}
	_, s.Rule = m.record.Get("finality")
	ref, _ := m.record.Get("referent")
	ro, _ := ref.(*canon.Object)
	if w, ok := ro.Get("window"); ok && ro != nil {
		wo := w.(*canon.Object)
		s.From = Boundary{Unit: "date", Date: datePart(str(wo, "from"))}
		s.To = Boundary{Unit: "date", Date: datePart(str(wo, "to"))}
	} else if at := str(ro, "at"); at != "" {
		s.From = Boundary{Unit: "date", Date: datePart(at)}
	}
	return s
}

func datePart(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// Segment is one segment of the current edition and its re-checked state.
type Segment struct {
	Member string
	SegmentState
}

// Series is the view of a growing series at one edition.
type Series struct {
	Resource, Edition string
	Declared          Boundary
	Computed          Boundary
	// ComputedState is "computed", "unchecked" or "no segments"; Why explains unchecked.
	ComputedState string
	Provisional   int
	// Comparison is "agrees", "flagged" (declared later than computed), "not comparable", or "unchecked".
	Comparison string
	Segments   []Segment
	// Revised lists every authorized edition of the resource that rewrites a segment below its predecessor's
	// declared boundary, with the segments it dropped or added there.
	Revised map[string][]string
	Explain []string
}

// Series resolves the series view of resource id at edition (its current edition when edition is "").
func (r *Resolver) Series(id, edition string) (*Series, bool) {
	res, ok := r.Resource(id)
	if !ok {
		return nil, false
	}
	if edition == "" {
		edition = res.Current
	}
	e, ok := res.Edition(edition)
	if !ok || e.State != Authorized {
		return nil, false
	}
	sr := r.rules.segments
	if sr == nil {
		sr = RecordSegments{}
	}
	s := &Series{Resource: id, Edition: e.ID, Declared: declared(e.Body), Revised: map[string][]string{}}
	positions := map[string]SegmentState{}
	segsOf := func(ed *Edition) map[string]*Member {
		out := map[string]*Member{}
		for _, m := range r.editionMembers(ed) {
			if m.Role == "segment" {
				out[m.Key] = m
				if _, ok := positions[m.Key]; !ok {
					positions[m.Key] = sr.Segment(m)
				}
			}
		}
		return out
	}
	for _, k := range sortedKeys(segsOf(e)) {
		s.Segments = append(s.Segments, Segment{Member: k, SegmentState: positions[k]})
	}
	slices.SortStableFunc(s.Segments, func(a, b Segment) int {
		if c, ok := a.From.compare(b.From); ok {
			return c
		}
		return strings.Compare(a.From.Unit, b.From.Unit)
	})
	s.compute()
	s.compare()

	// REVISED-FROZEN: every authorized edition against each predecessor that declared a boundary.
	for _, ed := range res.Editions {
		if ed.State != Authorized {
			continue
		}
		mine := segsOf(ed)
		for _, pid := range ed.Predecessors {
			pe, ok := res.Edition(pid)
			if !ok || pe.ID != pid {
				continue // the genesis
			}
			d := declared(pe.Body)
			if d.Unit == "" {
				continue
			}
			theirs := segsOf(pe)
			var changed []string
			below := func(k string) {
				c, ok := positions[k].From.compare(d)
				switch {
				case ok && c < 0:
					changed = append(changed, k)
				case !ok:
					s.Explain = append(s.Explain, fmt.Sprintf("edition %s: segment %s position %s not comparable with %s's frozen_before %s",
						keylog.Short(ed.ID), shortMember(k), positions[k].From, keylog.Short(pe.ID), d))
				}
			}
			for _, k := range sortedKeys(theirs) {
				if mine[k] == nil {
					below(k)
				}
			}
			for _, k := range sortedKeys(mine) {
				if theirs[k] == nil {
					below(k)
				}
			}
			if len(changed) > 0 {
				s.Revised[ed.ID] = append(s.Revised[ed.ID], changed...)
				s.Explain = append(s.Explain, fmt.Sprintf("%s %s: rewrites segment(s) %s below %s's frozen_before %s",
					RevisedFrozen, keylog.Short(ed.ID), strings.Join(shortMembers(changed), ","), keylog.Short(pe.ID), d))
			}
		}
	}
	return s, true
}

func declared(body *canon.Object) Boundary {
	contents, _ := body.Get("contents")
	c, _ := contents.(*canon.Object)
	fv, ok := c.Get("frozen_before")
	if !ok {
		return Boundary{}
	}
	f := fv.(*canon.Object)
	switch {
	case str(f, "date") != "":
		return Boundary{Unit: "date", Date: str(f, "date")}
	case str(f, "run") != "":
		return Boundary{Unit: "run", Run: str(f, "run")}
	}
	h, _ := f.Get("height")
	return Boundary{Unit: "height", Height: int64(h.(canon.Int))}
}

// compute derives the members' finality boundary from the segments' re-checked states.
func (s *Series) compute() {
	if len(s.Segments) == 0 {
		s.ComputedState = "no segments"
		return
	}
	var units []string
	for _, g := range s.Segments {
		if !g.Rule {
			s.ComputedState = "unchecked"
			s.Explain = append(s.Explain, "segment "+shortMember(g.Member)+" carries no finality rule")
			continue
		}
		if g.Final != "final" && g.Final != "provisional" {
			s.ComputedState = "unchecked"
			s.Explain = append(s.Explain, "segment "+shortMember(g.Member)+": "+g.Why)
		}
		units = append(units, g.From.Unit)
	}
	if s.ComputedState == "unchecked" {
		return
	}
	if distinct := slices.Compact(slices.Sorted(slices.Values(units))); len(distinct) != 1 || distinct[0] == "" {
		s.ComputedState = "unchecked"
		s.Explain = append(s.Explain, "segment positions are unknown or in different units: "+strings.Join(distinct, ","))
		return
	}
	s.ComputedState = "computed"
	for _, g := range s.Segments {
		if g.Final == "provisional" {
			s.Provisional++
			if s.Provisional == 1 {
				s.Computed = g.From
			}
		}
	}
	if s.Provisional == 0 {
		last := s.Segments[len(s.Segments)-1]
		s.Computed = last.To
		if s.Computed.Unit == "" {
			s.Computed = last.From
		}
	}
}

func (s *Series) compare() {
	switch {
	case s.Declared.Unit == "":
		s.Comparison = "unchecked"
		s.Explain = append(s.Explain, "no frozen_before declared")
	case s.ComputedState != "computed":
		s.Comparison = "unchecked"
	case s.Declared.Unit != s.Computed.Unit:
		s.Comparison = "not comparable"
		s.Explain = append(s.Explain, fmt.Sprintf("declared in %s, members' rules compute a %s: not converted", s.Declared.Unit, s.Computed.Unit))
	default:
		c, ok := s.Declared.compare(s.Computed)
		switch {
		case !ok:
			s.Comparison = "not comparable"
			s.Explain = append(s.Explain, "run labels carry no order this reader knows")
		case c > 0:
			s.Comparison = "flagged"
			s.Explain = append(s.Explain, "declared boundary is later than the members' finality boundary")
		default:
			s.Comparison = "agrees"
		}
	}
}

// Line is the one-line display: declared beside computed.
func (s *Series) Line() string {
	decl := "frozen_before undeclared"
	if s.Declared.Unit != "" {
		decl = "frozen_before " + s.Declared.String() + " (declared)"
	}
	var comp string
	switch s.ComputedState {
	case "computed":
		comp = "members final to " + s.Computed.String()
		if s.Provisional > 0 {
			comp += " (" + plural(s.Provisional, "segment") + " provisional)"
		}
	case "no segments":
		comp = "members: no segments"
	default:
		comp = "members' finality unchecked"
	}
	line := decl + " · " + comp
	switch s.Comparison {
	case "flagged":
		line += " · FLAGGED: declared later than computed"
	case "not comparable":
		line += " · not comparable"
	}
	return line
}

// Render is the series display.
func (s *Series) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "series %s at %s\n  %s\n", keylog.Short(s.Resource), keylog.Short(s.Edition), s.Line())
	for _, g := range s.Segments {
		fmt.Fprintf(&b, "  segment %s from %s: %s\n", shortMember(g.Member), g.From, g.Final)
	}
	for _, id := range sortedKeys(s.Revised) {
		fmt.Fprintf(&b, "  %s %s\n", RevisedFrozen, keylog.Short(id))
	}
	for _, x := range s.Explain {
		fmt.Fprintf(&b, "  %s\n", x)
	}
	return b.String()
}

// FreezePolicy is a hub's (or any reader's) own policy on series editions (§8: "a hub can refuse a premature
// freeze under its own policy"). It returns nil to endorse.
type FreezePolicy interface {
	CheckSeries(s *Series) *refusal.Refusal
}

// PrematureFreeze is the refusal reason of RequireDeclaredNotAfterComputed.
const PrematureFreeze = "premature freeze"

// RequireDeclaredNotAfterComputed is the policy of C-core-104: the declared boundary must not be later than
// the members' computed one. A boundary the reader cannot compare is refused too: under this policy an
// unverifiable freeze is not endorsed (I4).
type RequireDeclaredNotAfterComputed struct{}

// CheckSeries implements FreezePolicy.
func (RequireDeclaredNotAfterComputed) CheckSeries(s *Series) *refusal.Refusal {
	if s.Comparison == "agrees" {
		return nil
	}
	return &refusal.Refusal{Class: refusal.Policy, Reason: PrematureFreeze,
		Detail: fmt.Sprintf("scope series edition %s of %s: %s", keylog.Short(s.Edition), keylog.Short(s.Resource), s.Line())}
}

// EndorseSeries applies the reader's freeze policy to a series edition. A refusal is the reader's policy
// only: the edition stays a valid, authorized edition in the resource view (I8).
func (r *Resolver) EndorseSeries(id, edition string, p FreezePolicy) (*Series, *refusal.Refusal) {
	s, ok := r.Series(id, edition)
	if !ok {
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: EditionNotHeld,
			Detail: fmt.Sprintf("series edition %s of %s not held; fetch it", keylog.Short(edition), keylog.Short(id))}
	}
	if p == nil {
		return s, nil
	}
	return s, p.CheckSeries(s)
}
