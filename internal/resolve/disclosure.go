package resolve

import (
	"fmt"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/canon"
)

// Availability and shelf life as the reader shows them (claims-model note §7: the disclosure table, "availability
// can be withheld"; wire §5 `availability`, `shelf_life_days`).
//
// Availability keeps its two declared values apart: whether redistribution is permitted and whether the bytes
// are obtainable are separate questions, and neither is shown as the other (C-core-68). A withheld availability
// is a commitment now and a reveal later: the reveal is a `holds` whose bytes match the statement's hash (I1).
// Before bytes are verified a `holds` is its signer's word, so the display says "revealed" only when a `holds`
// exists and this reader holds the bytes, re-hashed (C-core-75); a holds that served other bytes installed
// nothing and leaves the statement withheld (C-core-76). The reader's own copy without any `holds` (the author's
// store after `publish --no-holds`) is not a reveal.
//
// Shelf life is the publisher's declared validity beside the age at read time (C-core-74). The age is counted
// from a time the reader verified: the header time of the block a verified anchor commits in (miner-reported,
// bitcoin-time note §8). A local or self-declared time orders nothing and is not turned into an age (§10: local
// quality is shown as `(local, self-declared)`, never as a time), so without a verified bound the age reads
// `unknown`. The read time is an input the reader passes (WithReadTime), never the resolver's own clock, so the
// answer stays a function of the held set and the time context (I14; storage note §5.1). Neither disclosure moves
// the grade or the exit (I6).

// WithReadTime sets the reader's evaluation time for answers that depend on it (shelf-life age). Without it no
// age is computed.
func WithReadTime(t time.Time) Option {
	return func(r *Resolver) { u := t.UTC(); r.readTime = &u }
}

// Availability is the availability disclosure of one blob.
type Availability struct {
	// Declared is true when the field has a default value; the members below are that value.
	Declared       bool
	Redistribution string // "permitted", "restricted" or "withheld"
	Obtainable     bool   // as declared
	WithheldUntil  string // the declared condition, "" when none
	// Held is true when the reader holds the bytes, verified by full hash (BlobIndex).
	Held bool
	// Revealed is true for a withheld availability when some key's serving `holds` exists and the bytes it names
	// are held and verified here.
	Revealed bool
	Display  string
}

// ShelfLife is the shelf-life disclosure of one blob.
type ShelfLife struct {
	Declared bool
	Days     int64
	// Age is the age in whole days at the read time; valid only when Aged.
	Age  int64
	Aged bool
	// Since is the verified bound the age is counted from (a zero Quality when none).
	Since Bound
	// UsedReadTime is true when the answer depended on the reader's evaluation time.
	UsedReadTime bool
	Display      string
}

// availability resolves a's availability disclosure. It needs a.Fields and a.Holders.
func (r *Resolver) availability(a *Artifact) *Availability {
	f := a.Field("availability")
	v, ok := f.Default()
	if !ok {
		return nil
	}
	o := parseObj(v)
	if o == nil {
		return nil
	}
	av := &Availability{Declared: true, Redistribution: str(o, "redistribution"), WithheldUntil: str(o, "withheld_until")}
	if b, ok := o.Members["obtainable"].(canon.Bool); ok {
		av.Obtainable = bool(b)
	}
	av.Held = r.obs.blobs.Has(a.Digest)
	var parts []string
	red := "redistribution " + av.Redistribution
	if av.Redistribution == "withheld" && av.WithheldUntil != "" {
		red = "redistribution withheld until " + quoteInert(av.WithheldUntil)
	}
	parts = append(parts, red)
	if av.Obtainable {
		parts = append(parts, "bytes obtainable (declared)")
	} else {
		parts = append(parts, "bytes not obtainable (declared)")
	}
	holders := make([]string, len(a.Holders))
	for i, h := range a.Holders {
		holders[i] = shortKey(h)
	}
	switch {
	case av.Redistribution == "withheld" && len(a.Holders) > 0 && av.Held:
		av.Revealed = true
		parts = append(parts, "revealed: holds by "+strings.Join(holders, ",")+", bytes held here and verified by full hash")
	case av.Redistribution == "withheld" && len(a.Holders) > 0:
		parts = append(parts, "holds by "+strings.Join(holders, ",")+" (holder's word; the reveal is not verified until the bytes are)")
	case av.Redistribution == "withheld" && av.Held:
		parts = append(parts, "bytes held here, no holds published (not revealed)")
	case av.Redistribution == "withheld":
		parts = append(parts, "not revealed (no holds held)")
	}
	av.Display = strings.Join(parts, " · ")
	return av
}

// shelfLife resolves a's shelf-life disclosure. It needs a.Fields.
func (r *Resolver) shelfLife(a *Artifact) *ShelfLife {
	f := a.Field("shelf_life_days")
	v, ok := f.Default()
	if !ok {
		return nil
	}
	n, err := canon.Parse([]byte(v))
	days, isInt := n.(canon.Int)
	if err != nil || !isInt {
		return nil
	}
	s := &ShelfLife{Declared: true, Days: int64(days)}
	// the bound of the statements that declare the default value: the earliest verified one
	best := Bound{Quality: NoBound}
	var ts []string
	for _, src := range f.From {
		if p, ok := r.byID[src.Statement]; ok {
			best = better(best, r.bound(p.St))
			ts = append(ts, p.St.TS.Text)
		}
	}
	decl := fmt.Sprintf("%d days declared", s.Days)
	switch {
	case !best.verified() || best.Time == 0:
		why := "no verified time"
		if best.verified() {
			why = "the verified anchor carries no block time"
		}
		s.Display = decl + "; age unknown (" + why + "; signer-declared " + strings.Join(ts, ",") + ", (local, self-declared))"
	case r.readTime == nil:
		s.Since = best
		s.Display = decl + "; age not computed (no read time given)"
	default:
		s.Since, s.UsedReadTime = best, true
		at := time.Unix(best.Time, 0).UTC()
		since := fmt.Sprintf("since bitcoin height %d (header time %s, miner-reported)", best.Height, at.Format(time.RFC3339))
		d := r.readTime.Sub(at)
		if d < 0 {
			s.Display = decl + "; age unknown (the anchor's block time is after the read time " + r.readTime.Format(time.RFC3339) + ")"
			break
		}
		s.Age, s.Aged = int64(d/(24*time.Hour)), true
		verdict := "within declared validity (counted from the anchor)"
		if s.Age > s.Days {
			verdict = "past declared validity"
		}
		s.Display = fmt.Sprintf("%s; age %d days %s, %s", decl, s.Age, since, verdict)
	}
	return s
}

func parseObj(v string) *canon.Object {
	x, err := canon.Parse([]byte(v))
	if err != nil {
		return nil
	}
	o, _ := x.(*canon.Object)
	return o
}

// quoteInert renders peer-written prose as a quoted string, so it cannot pass for display structure.
func quoteInert(s string) string { return string(canon.Encode(canon.String(s))) }

// renderDisclosure is the display line of availability and shelf life when they have a structured reading.
func (a *Artifact) renderDisclosure(name string) (string, bool) {
	switch {
	case name == "availability" && a.Availability != nil:
		return a.Availability.Display, true
	case name == "shelf_life_days" && a.ShelfLife != nil:
		return a.ShelfLife.Display, true
	}
	return "", false
}
