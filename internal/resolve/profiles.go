package resolve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
)

// Source profiles (claims-model note §5.3.1a; wire-format note §5, "Finality rules and source profiles").
//
// A source profile is a content-addressed blob stating one source's finality policy in one of the two dialects
// the format defines: integer depth (`confirmations >= N` over `state_at_capture.depth`) or ordered label
// (`run >= L` over `state_at_capture.run`, ordered by the profile's closed list of labels). A reader resolves a
// statement's `finality.rule_source` against the profiles it chose: the profile whose digest it is, or whose
// `documents` list it. No profile, or two, leaves an ordered-label rule unchecked, naming why; a label not in
// the list is not comparable, never ordered by its spelling.
//
// A profile evaluates the observer's asserted state, not the source: whatever it decides is "as captured, not
// re-checked" (I4). ProfileSegments is the series segment reader built on it.

// SourceProfileTag is the format tag of a source profile blob.
const SourceProfileTag = "rc-source-profile/1"

// The two finality dialects the format defines.
const (
	DialectOrderedLabel = "ordered-label"
	DialectIntegerDepth = "integer-depth"
)

// MaxProfileLabels bounds a profile's label list.
const MaxProfileLabels = 4096

// MaxProfileBytes bounds a profile blob a receiver loads.
const MaxProfileBytes = 1 << 20

// SourceProfile is one parsed `rc-source-profile/1` blob.
type SourceProfile struct {
	Digest      string
	Source      string
	Dialect     string
	Labels      []string
	Documents   []string
	Description string
	index       map[string]int
	// Layout is the response layout the profile cites in its documents (layout.go), nil when none or unusable;
	// layoutWhy says why a cited layout is unusable.
	Layout    *ResponseLayout
	layoutWhy string
}

// ParseSourceProfile reads a source profile blob. The bytes must be canonical JSON carrying only the members the
// wire-format note defines, within their constraints; anything else is not a profile, and the error says why.
func ParseSourceProfile(b []byte) (*SourceProfile, error) {
	if len(b) > MaxProfileBytes {
		return nil, fmt.Errorf("larger than %d bytes", MaxProfileBytes)
	}
	sum := sha256.Sum256(b)
	p := &SourceProfile{Digest: "sha256:" + hex.EncodeToString(sum[:]), index: map[string]int{}}
	v, err := canon.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("not canonical JSON: %v", err)
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, fmt.Errorf("top level is not an object")
	}
	if !bytes.Equal(canon.Encode(o), b) {
		return nil, fmt.Errorf("not in canonical form")
	}
	strs := func(k string, val canon.Value) ([]string, error) {
		arr, ok := val.(canon.Array)
		if !ok {
			return nil, fmt.Errorf("%s is not a list", k)
		}
		var out []string
		seen := map[string]bool{}
		for i, e := range arr {
			s, ok := e.(canon.String)
			if !ok || s == "" {
				return nil, fmt.Errorf("%s[%d] is not a non-empty string", k, i)
			}
			if seen[string(s)] {
				return nil, fmt.Errorf("%s[%d] %q repeats an entry", k, i, inertText(string(s)))
			}
			seen[string(s)] = true
			out = append(out, string(s))
		}
		return out, nil
	}
	var hasLabels bool
	for _, k := range o.Keys {
		val := o.Members[k]
		switch k {
		case "profile":
			if s, ok := val.(canon.String); !ok || string(s) != SourceProfileTag {
				return nil, fmt.Errorf("profile is not %q", SourceProfileTag)
			}
		case "source", "dialect", "description":
			s, ok := val.(canon.String)
			if !ok {
				return nil, fmt.Errorf("%s is not a string", k)
			}
			switch k {
			case "source":
				p.Source = string(s)
			case "dialect":
				p.Dialect = string(s)
			default:
				p.Description = string(s)
			}
		case "labels":
			hasLabels = true
			if p.Labels, err = strs(k, val); err != nil {
				return nil, err
			}
		case "documents":
			if p.Documents, err = strs(k, val); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("undefined member %q", inertText(k))
		}
	}
	if _, ok := o.Get("profile"); !ok {
		return nil, fmt.Errorf("missing required member \"profile\"")
	}
	if p.Source == "" {
		return nil, fmt.Errorf("source is missing or empty")
	}
	switch p.Dialect {
	case DialectOrderedLabel:
		if len(p.Labels) == 0 || len(p.Labels) > MaxProfileLabels {
			return nil, fmt.Errorf("an ordered-label profile needs 1 to %d labels, not %d", MaxProfileLabels, len(p.Labels))
		}
		for i, l := range p.Labels {
			if strings.TrimSpace(l) != l {
				return nil, fmt.Errorf("labels[%d] %q has surrounding whitespace", i, inertText(l))
			}
			p.index[l] = i
		}
	case DialectIntegerDepth:
		if hasLabels {
			return nil, fmt.Errorf("an integer-depth profile carries no labels")
		}
	case "":
		return nil, fmt.Errorf("dialect is missing")
	default:
		return nil, fmt.Errorf("dialect %q is not one the format defines (%s, %s)", inertText(p.Dialect), DialectOrderedLabel, DialectIntegerDepth)
	}
	return p, nil
}

func inertText(s string) string {
	q := strconv.QuoteToASCII(s)
	q = q[1 : len(q)-1]
	if len(q) > 80 {
		q = q[:80] + "..."
	}
	return q
}

// ProfileMatchExact is how a rule_source is matched to a profile, said wherever a match fails: byte for byte, with
// no normalization of a location (case, a trailing slash, percent-encoding) or of a digest's spelling.
const ProfileMatchExact = "rule_source compared as written to each profile's digest and documents"

// names reports whether ruleSource names this profile: it equals, byte for byte, its digest or one of its
// documents (ProfileMatchExact).
func (p *SourceProfile) names(ruleSource string) bool {
	return ruleSource != "" && (ruleSource == p.Digest || slices.Contains(p.Documents, ruleSource))
}

var reLabelRule = regexp.MustCompile(`^\s*run\s*(>=|≥)\s*(\S(?:.*\S)?)\s*$`)

// ProfileRules is the reader's chosen source profiles. As a FinalityRules it has no rule_source to resolve, so it
// evaluates depth rules as DepthRules does and leaves every ordered-label rule unevaluated; For binds it to one
// statement's rule_source.
type ProfileRules struct {
	profiles []*SourceProfile
	// bytes reads a held response for a profile's response layout (WithBytes); nil holds nothing.
	bytes BlobBytes
	steps int
	reads *layoutCache
}

// WithBytes is the rules reading held responses through get for the profiles' response layouts, each read within
// steps (DefaultLayoutSteps when < 1). Without it, every layout read is unchecked (response not held).
func (pr ProfileRules) WithBytes(get BlobBytes, steps int) ProfileRules {
	pr.bytes, pr.steps, pr.reads = get, steps, &layoutCache{m: map[[2]string][2]string{}}
	return pr
}

// NewProfileRules is the reader's profile set; repeats of one digest are one profile.
func NewProfileRules(ps ...*SourceProfile) ProfileRules {
	var out ProfileRules
	for _, p := range ps {
		if p != nil && !slices.ContainsFunc(out.profiles, func(q *SourceProfile) bool { return q.Digest == p.Digest }) {
			out.profiles = append(out.profiles, p)
		}
	}
	slices.SortFunc(out.profiles, func(a, b *SourceProfile) int { return strings.Compare(a.Digest, b.Digest) })
	return out
}

// Profiles lists the chosen profiles' digests, sorted.
func (pr ProfileRules) Profiles() []string {
	var out []string
	for _, p := range pr.profiles {
		out = append(out, p.Digest)
	}
	return out
}

// For binds the rules to one statement's rule_source.
func (pr ProfileRules) For(ruleSource string) BoundRules {
	b := BoundRules{RuleSource: ruleSource, bytes: pr.bytes, steps: pr.steps, reads: pr.reads}
	var hits []*SourceProfile
	for _, p := range pr.profiles {
		if p.names(ruleSource) {
			hits = append(hits, p)
		}
	}
	switch {
	case ruleSource == "":
		b.why = "the rule cites no rule_source, so no source profile orders its labels"
	case len(hits) == 0:
		b.why = "rule_source " + inertText(ruleSource) + " names no source profile this reader chose (" + ProfileMatchExact + ")"
	case len(hits) > 1:
		b.why = fmt.Sprintf("rule_source %s names %d source profiles this reader chose (%s); none is picked", inertText(ruleSource), len(hits),
			strings.Join(shortDigests(hits), ", "))
	default:
		b.Profile = hits[0]
	}
	return b
}

func shortDigests(ps []*SourceProfile) []string {
	var out []string
	for _, p := range ps {
		out = append(out, keylog.Short(p.Digest))
	}
	return out
}

// Evaluate implements FinalityRules: no rule_source is known here (see For).
func (pr ProfileRules) Evaluate(rule string, s State) (bool, string, bool) {
	return pr.For("").Evaluate(rule, s)
}

// Compare implements FinalityRules: no rule_source is known here (see For).
func (pr ProfileRules) Compare(rule string, a, b State) (int, bool) {
	return pr.For("").Compare(rule, a, b)
}

// BoundRules is ProfileRules resolved against one rule_source: the one profile it names, or none (with why).
type BoundRules struct {
	RuleSource string
	Profile    *SourceProfile
	why        string
	bytes      BlobBytes
	steps      int
	reads      *layoutCache
}

// Check evaluates rule at state s: whether it is met, the final state's display, and, when the rule cannot be
// evaluated, why ("" when it can).
func (b BoundRules) Check(rule string, s State) (met bool, final string, why string) {
	if reDepthRule.MatchString(rule) {
		met, final, known := DepthRules{}.Evaluate(rule, s)
		if !known {
			return false, "", "the depth rule needs a depth state, the capture records " + stateKind(s)
		}
		return met, final, ""
	}
	m := reLabelRule.FindStringSubmatch(rule)
	if m == nil {
		return false, "", fmt.Sprintf("rule %q is in neither finality dialect the format defines", inertText(rule))
	}
	l := m[2]
	p := b.Profile
	switch {
	case p == nil:
		return false, "", b.why
	case p.Dialect != DialectOrderedLabel:
		return false, "", "source profile " + keylog.Short(p.Digest) + " is " + p.Dialect + ", the rule is ordered-label"
	}
	ri, ok := p.index[l]
	if !ok {
		return false, "", fmt.Sprintf("rule label %q is not in source profile %s: not comparable", inertText(l), keylog.Short(p.Digest))
	}
	if s.Run == "" {
		return false, "", "the label rule needs a run state, the capture records " + stateKind(s)
	}
	si, ok := p.index[s.Run]
	if !ok {
		return false, "", fmt.Sprintf("state %q is not in source profile %s: not comparable", inertText(s.Run), keylog.Short(p.Digest))
	}
	return si >= ri, l, ""
}

// ordersLabels reports whether rules are bound to a profile that orders rule's labels: an ordered-label rule whose
// label is in an ordered-label profile. Under it a state the profile cannot place is not comparable (claims-model
// note §5.3.1a), not a rule the reader cannot evaluate.
func ordersLabels(rules FinalityRules, rule string) bool {
	b, ok := rules.(BoundRules)
	if !ok {
		return false
	}
	m := reLabelRule.FindStringSubmatch(rule)
	if m == nil || b.Profile == nil || b.Profile.Dialect != DialectOrderedLabel {
		return false
	}
	_, ok = b.Profile.index[m[2]]
	return ok
}

// underProfile names the source profile that ordered an ordered-label rule's states, for a history line; "" when
// no profile did (a depth rule, or rules not bound to a profile).
func underProfile(rules FinalityRules, rule string) string {
	b, ok := rules.(BoundRules)
	if !ok || b.Profile == nil || b.Profile.Dialect != DialectOrderedLabel || !reLabelRule.MatchString(rule) {
		return ""
	}
	return " under source profile " + keylog.Short(b.Profile.Digest)
}

func stateKind(s State) string {
	switch {
	case s.HasDepth:
		return "a depth"
	case s.Run != "":
		return "a run label"
	case s.CapturedAt != "":
		return "a capture time"
	}
	return "no state"
}

// Evaluate implements FinalityRules.
func (b BoundRules) Evaluate(rule string, s State) (bool, string, bool) {
	met, final, why := b.Check(rule, s)
	return met, final, why == ""
}

// Compare implements FinalityRules: depths as integers; labels by their index in the bound profile, a label
// outside it comparable with nothing; without a profile, two equal labels are one state and nothing else is
// ordered (wire-format note §5 `finality`).
func (b BoundRules) Compare(rule string, x, y State) (int, bool) {
	if reLabelRule.MatchString(rule) && b.Profile != nil && b.Profile.Dialect == DialectOrderedLabel {
		i, ok1 := b.Profile.index[x.Run]
		j, ok2 := b.Profile.index[y.Run]
		if ok1 && ok2 && x.Run != "" && y.Run != "" {
			return cmpInt(int64(i), int64(j)), true
		}
		return 0, false
	}
	return DepthRules{}.Compare(rule, x, y)
}

// ProfileSegments is a SegmentReader that reads each segment's finality from its own statement's asserted state at
// capture, under the reader's chosen source profiles, or, when the profile cites a response layout and the segment's
// held response reads under it, from the held bytes (Held). It re-checks no source: every state it reports final or
// provisional is as captured or as held, and the series boundary it yields is marked so (claims-model note §8, "a
// boundary as captured"). The position is read as RecordSegments reads it.
type ProfileSegments struct {
	Rules ProfileRules
}

// Segment implements SegmentReader.
func (ps ProfileSegments) Segment(m *Member) SegmentState {
	s := RecordSegments{}.Segment(m)
	if m.record == nil {
		return s
	}
	if !s.Rule {
		s.Why = "carries no finality rule"
		return s
	}
	fo := object(m.record, "finality")
	rule := str(fo, "rule")
	b := ps.Rules.For(str(fo, "rule_source"))
	state, lr := heldState(b, rule, m.record, stateOf(object(fo, "state_at_capture")))
	met, _, why := b.Check(rule, state)
	if why != "" {
		s.Final, s.Why = "unchecked", why
		return s
	}
	// read from the held response under the profile's layout, or the asserted state: neither re-checks the source
	s.Final, s.Why, s.AsCaptured, s.Held = "provisional", "", true, lr != nil && lr.State != ""
	if met {
		s.Final = "final"
	}
	return s
}
