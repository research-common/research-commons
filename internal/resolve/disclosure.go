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

// ReadTime is the evaluation time the reader passed (zero when none).
func (r *Resolver) ReadTime() time.Time {
	if r.readTime == nil {
		return time.Time{}
	}
	return *r.readTime
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
	// Holders are the keys with a serving `holds` for the blob (Artifact.Holders): each one's word.
	Holders []string
	Display string
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
	av.Holders = a.Holders
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
	case name == "licence" && a.Licence != nil:
		return a.Licence.Display, true
	}
	return "", false
}

// Declared beside computed, and the scoped summary of a derived result (claims-model note §7). A derived result's
// inputs carry their own disclosures; the reader computes, over the direct inputs of the derivation it grades
// from, the weakest replication, the shortest shelf life and the per-input sampling n, each with its denominator
// (how many inputs declare it), and shows the result's own declared sampling n beside the n computed from its
// inputs, flagging a disagreement. Neither replaces the other, and none of it moves the grade (I6). The computed n
// is the sum of the inputs' n when every declaring input uses the result's unit; otherwise it is not computed and
// the display says why. An input's value is its default (an authored input) or the value its counted observations
// agree on (an observation input); a value they disagree on counts as undeclared and is named.

// InputN is one input's declared sampling.
type InputN struct {
	Input string
	N     int64
	Unit  string
}

// InputSummary is the scoped summary of a derived result's disclosures over its direct inputs.
type InputSummary struct {
	Inputs int
	// Replication is the weakest declared replication (bytes > protocol > none); ReplDeclared counts the inputs
	// that declare one.
	Replication  string
	ReplDeclared int
	// ShelfDays is the shortest declared shelf life; ShelfDeclared counts the inputs that declare one.
	ShelfDays     int64
	ShelfDeclared int
	// PerInput lists every input's declared sampling, in input order.
	PerInput []InputN
	// Computed is the n computed from the inputs, valid when NComputed; NWhy says why not otherwise.
	Computed  int64
	NComputed bool
	NWhy      string
	// Declared is the result's own declared n and unit (DeclaredOK when it declares one); Disagree flags a
	// computed n that differs from it.
	Declared   int64
	DeclUnit   string
	DeclaredOK bool
	Disagree   bool
	Notes      []string
	// Scope is the scope the summary holds within (§6 (1)).
	Scope string
}

var replRank = map[string]int{"bytes": 3, "protocol": 2, "none": 1}

// inputValue is input d's value of a disclosure: an authored input's default; an observation input's value its
// counted observations agree on. ok is false when undeclared or disagreed (why names which).
func (r *Resolver) inputValue(d, name string) (v canon.Value, ok bool, why string) {
	if r.isObservation(d) {
		ps, unmet := r.observedFor(d)
		if unmet != "" {
			return nil, false, unmet
		}
		var seen string
		for _, p := range ps {
			x, has := p.St.Body.Get(name)
			if !has {
				continue
			}
			e := string(canon.Encode(x))
			if seen != "" && e != seen {
				return nil, false, "its observations disagree"
			}
			seen, v = e, x
		}
		return v, v != nil, ""
	}
	a := r.authorship(d)
	f := a.Field(name)
	s, has := f.Default()
	if !has {
		if f.State == FieldContested || f.State == FieldNoDefault || f.State == FieldUnknown {
			return nil, false, string(f.State)
		}
		return nil, false, ""
	}
	x, err := canon.Parse([]byte(s))
	return x, err == nil, ""
}

// inputSummary computes a's summary over the direct inputs of the derivation it grades from (nil when a has no
// derivation group).
func (r *Resolver) inputSummary(a *Artifact) *InputSummary {
	if a.Group == nil || len(a.Group.Provenance.Inputs) == 0 {
		return nil
	}
	s := &InputSummary{Inputs: len(a.Group.Provenance.Inputs), ShelfDays: -1, Scope: r.obs.scope}
	if v, ok := a.Field("sampling").Default(); ok {
		if o := parseObj(v); o != nil {
			if n, ok := o.Members["n"].(canon.Int); ok {
				s.Declared, s.DeclUnit, s.DeclaredOK = int64(n), str(o, "unit"), true
			}
		}
	}
	units := map[string]bool{}
	var sum int64
	for _, in := range a.Group.Provenance.Inputs {
		if v, ok, why := r.inputValue(in, "replication"); ok {
			if m, isStr := v.(canon.String); isStr && replRank[string(m)] > 0 {
				s.ReplDeclared++
				if s.Replication == "" || replRank[string(m)] < replRank[s.Replication] {
					s.Replication = string(m)
				}
			}
		} else if why != "" {
			s.Notes = append(s.Notes, "replication of input "+shortDigest(in)+" not counted: "+why)
		}
		if v, ok, why := r.inputValue(in, "shelf_life_days"); ok {
			if n, isInt := v.(canon.Int); isInt {
				s.ShelfDeclared++
				if s.ShelfDays < 0 || int64(n) < s.ShelfDays {
					s.ShelfDays = int64(n)
				}
			}
		} else if why != "" {
			s.Notes = append(s.Notes, "shelf life of input "+shortDigest(in)+" not counted: "+why)
		}
		if v, ok, why := r.inputValue(in, "sampling"); ok {
			if o, isObj := v.(*canon.Object); isObj {
				if n, isInt := o.Members["n"].(canon.Int); isInt {
					s.PerInput = append(s.PerInput, InputN{Input: in, N: int64(n), Unit: str(o, "unit")})
					units[str(o, "unit")] = true
					sum += int64(n)
				}
			}
		} else if why != "" {
			s.Notes = append(s.Notes, "sampling of input "+shortDigest(in)+" not counted: "+why)
		}
	}
	switch {
	case len(s.PerInput) == 0:
		s.NWhy = "no input declares sampling"
	case len(units) > 1:
		s.NWhy = "inputs use different units (" + strings.Join(sortedKeys(units), ", ") + ")"
	case s.DeclaredOK && !units[s.DeclUnit]:
		s.NWhy = "inputs count " + s.PerInput[0].Unit + ", the result declares " + s.DeclUnit
	default:
		s.Computed, s.NComputed = sum, true
		s.Disagree = s.DeclaredOK && s.Declared != sum
	}
	return s
}

// samplingLine is the declared-beside-computed line for the result's sampling n.
func (s *InputSummary) samplingLine() string {
	decl := "undeclared"
	if s.DeclaredOK {
		decl = fmt.Sprintf("%d %s (declared)", s.Declared, s.DeclUnit)
	}
	comp := fmt.Sprintf("not computed: %s", s.NWhy)
	if s.NComputed {
		comp = fmt.Sprintf("%d %s (computed from %d of %d inputs)", s.Computed, s.PerInput[0].Unit, len(s.PerInput), s.Inputs)
	}
	line := "n " + decl + " · " + comp
	if s.Disagree {
		line += " · declared and computed disagree"
	}
	return line
}

// Lines is the summary as displayed beside the grade, scoped to the statements held.
func (s *InputSummary) Lines() []string {
	repl := fmt.Sprintf("replication: none declared by the %d inputs", s.Inputs)
	if s.ReplDeclared > 0 {
		repl = fmt.Sprintf("replication: %s (weakest; %d of %d inputs declare one)", s.Replication, s.ReplDeclared, s.Inputs)
	}
	shelf := fmt.Sprintf("shelf life: none declared by the %d inputs", s.Inputs)
	if s.ShelfDeclared > 0 {
		shelf = fmt.Sprintf("shelf life: %d days (shortest; %d of %d inputs declare one)", s.ShelfDays, s.ShelfDeclared, s.Inputs)
	}
	var per []string
	for _, p := range s.PerInput {
		per = append(per, fmt.Sprintf("%s %d %s", shortDigest(p.Input), p.N, p.Unit))
	}
	n := fmt.Sprintf("sampling per input: none of the %d inputs declares sampling", s.Inputs)
	if len(per) > 0 {
		n = fmt.Sprintf("sampling per input (%d of %d declare): %s", len(per), s.Inputs, strings.Join(per, ", "))
	}
	out := []string{repl, shelf, n, "sampling " + s.samplingLine()}
	for i := range out {
		out[i] += " (" + s.Scope + ")"
	}
	return append(out, s.Notes...)
}
