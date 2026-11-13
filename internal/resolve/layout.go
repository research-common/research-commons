package resolve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
)

// Response layouts (claims-model note §5.3.1a, "Response layouts"; wire-format note §5).
//
// A response layout says where a source's finality state sits in a captured JSON response: an RFC 6901 pointer to
// the array of records (`records`; absent for a response that carries one state) and an RFC 6901 pointer to the
// state within each record (`state`; within the response when `records` is absent). A source profile cites its
// layout by digest in `documents`, so a reader that does not implement layouts reads the profile exactly as before
// (the layout is one more cited document to it).
//
// Reading a state is a pure function of the held response bytes, the layout and the profile's label order: every
// record must carry a non-empty string at the state pointer that is a label in the profile, and the response reads
// at its least record (the earliest label in the profile's order among the records). The finality rule is monotone
// (`run >= L`), so the response meets it exactly when every record does: the least record is the one state the
// whole response can be relied on at, never an upgrade. When records differ the read discloses the spread. Anything
// else (a record whose value is missing, not a string, empty or outside the profile, a pointer that names nothing,
// bytes that are not I-JSON, a response that is not held or exceeds the caps) reads `unchecked`, naming why, and the
// observer's asserted state is used exactly as without a layout, never upgraded.

// ResponseLayoutTag is the format tag of a response layout blob.
const ResponseLayoutTag = "rc-response-layout/1"

// Reader caps for layouts (documented limits; each over-cap case reads unchecked, naming the cap).
const (
	// MaxLayoutBytes bounds a layout blob.
	MaxLayoutBytes = 64 << 10
	// MaxPointerBytes bounds one pointer's text.
	MaxPointerBytes = 1024
	// MaxResponseBytes bounds a captured response a layout reads.
	MaxResponseBytes = 16 << 20
	// DefaultLayoutSteps is the step budget of one layout read: every record visited and every pointer token
	// followed counts one.
	DefaultLayoutSteps = 1 << 20
)

// LayoutStepLimit names the step budget in an unchecked read.
const LayoutStepLimit = "layout step limit"

// ResponseLayout is one parsed `rc-response-layout/1` blob.
type ResponseLayout struct {
	Digest string
	// Records is the pointer to the record array; HasRecords is false when the layout reads one state.
	Records    []string
	HasRecords bool
	// State is the pointer to the state within each record (or within the response).
	State       []string
	RecordsText string
	StateText   string
	Description string
}

// IsResponseLayout reports whether b claims to be a response layout: a JSON object whose `layout` member is a
// string beginning "rc-response-layout/". Such a blob is judged as a layout (and may fail as one); any other
// document a profile cites is an ordinary document.
func IsResponseLayout(b []byte) bool {
	if len(b) > MaxLayoutBytes {
		return false
	}
	v, err := canon.Parse(b)
	if err != nil {
		return false
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return false
	}
	s, ok := o.Members["layout"].(canon.String)
	return ok && strings.HasPrefix(string(s), "rc-response-layout/")
}

// ParseResponseLayout reads a layout blob: canonical JSON carrying only the members the wire-format note defines,
// pointers that are syntactically RFC 6901 within MaxPointerBytes and the depth limit. Anything else is not a
// layout, and the error says why.
func ParseResponseLayout(b []byte) (*ResponseLayout, error) {
	if len(b) > MaxLayoutBytes {
		return nil, fmt.Errorf("larger than %d bytes", MaxLayoutBytes)
	}
	sum := sha256.Sum256(b)
	l := &ResponseLayout{Digest: "sha256:" + hex.EncodeToString(sum[:])}
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
	var hasState bool
	for _, k := range o.Keys {
		s, isStr := o.Members[k].(canon.String)
		switch k {
		case "layout":
			if !isStr || string(s) != ResponseLayoutTag {
				return nil, fmt.Errorf("layout is not %q", ResponseLayoutTag)
			}
		case "records", "state":
			if !isStr {
				return nil, fmt.Errorf("%s is not a string", k)
			}
			toks, err := ParsePointer(string(s))
			if err != nil {
				return nil, fmt.Errorf("%s is not an RFC 6901 JSON pointer: %v", k, err)
			}
			if k == "records" {
				l.Records, l.HasRecords, l.RecordsText = toks, true, string(s)
			} else {
				l.State, hasState, l.StateText = toks, true, string(s)
			}
		case "description":
			if !isStr {
				return nil, fmt.Errorf("description is not a string")
			}
			l.Description = string(s)
		default:
			return nil, fmt.Errorf("undefined member %q", inertText(k))
		}
	}
	if _, ok := o.Get("layout"); !ok {
		return nil, fmt.Errorf("missing required member \"layout\"")
	}
	if !hasState {
		return nil, fmt.Errorf("missing required member \"state\"")
	}
	if len(l.Records)+len(l.State) > canon.MaxDepth {
		return nil, fmt.Errorf("records and state together name %d levels, past the depth limit %d", len(l.Records)+len(l.State), canon.MaxDepth)
	}
	return l, nil
}

// ParsePointer splits an RFC 6901 JSON pointer into its reference tokens, unescaped: "" is the whole document; any
// other pointer starts with "/", and "~" appears only as "~0" or "~1". At most MaxPointerBytes and canon.MaxDepth
// tokens (a deeper pointer can name nothing a reader parses).
func ParsePointer(p string) ([]string, error) {
	if len(p) > MaxPointerBytes {
		return nil, fmt.Errorf("longer than %d bytes", MaxPointerBytes)
	}
	if p == "" {
		return nil, nil
	}
	if p[0] != '/' {
		return nil, fmt.Errorf("does not start with \"/\"")
	}
	parts := strings.Split(p[1:], "/")
	if len(parts) > canon.MaxDepth {
		return nil, fmt.Errorf("%d reference tokens, past the depth limit %d", len(parts), canon.MaxDepth)
	}
	for i, t := range parts {
		for j := 0; j < len(t); j++ {
			if t[j] == '~' && (j+1 == len(t) || (t[j+1] != '0' && t[j+1] != '1')) {
				return nil, fmt.Errorf("reference token %d has a \"~\" that is not \"~0\" or \"~1\"", i)
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

// lookup follows tokens from v (RFC 6901 §4): an object member by name, an array element by a decimal index with no
// leading zeros. It returns the value, or why it names nothing. Each token costs one step.
func lookup(v canon.Value, toks []string, steps *int) (canon.Value, string) {
	for i, t := range toks {
		if *steps--; *steps < 0 {
			return nil, LayoutStepLimit
		}
		switch x := v.(type) {
		case *canon.Object:
			m, ok := x.Members[t]
			if !ok {
				return nil, fmt.Sprintf("no member %q at reference token %d", inertText(t), i)
			}
			v = m
		case canon.Array:
			n, err := strconv.Atoi(t)
			if err != nil || n < 0 || (len(t) > 1 && t[0] == '0') || strconv.Itoa(n) != t {
				return nil, fmt.Sprintf("reference token %d %q is not an array index", i, inertText(t))
			}
			if n >= len(x) {
				return nil, fmt.Sprintf("index %d is past the end of an array of %d at reference token %d", n, len(x), i)
			}
			v = x[n]
		default:
			return nil, fmt.Sprintf("reference token %d steps into a %s", i, kindOf(v))
		}
	}
	return v, ""
}

func kindOf(v canon.Value) string {
	switch v.(type) {
	case *canon.Object:
		return "object"
	case canon.Array:
		return "array"
	case canon.String:
		return "string"
	case canon.Int, canon.Number:
		return "number"
	case canon.Bool:
		return "boolean"
	case canon.Null:
		return "null"
	}
	return "value"
}

// LabelRank places a label in a source profile's order: its index (earliest state first) and whether the profile
// has the label at all. SourceProfile.Rank is the one a reader passes.
type LabelRank func(label string) (int, bool)

// StateRead is what ReadState found in one response.
type StateRead struct {
	// State is the least record's label under the profile's order ("" when the read is unchecked: Why).
	State string
	// Greatest is the latest label among the records: State when every record carries the same one.
	Greatest string
	// Records counts the records read (0 for a layout that reads one state).
	Records int
	Why     string
}

// Spread is the disclosure of records that differ, "records at R1..RF, read as R1"; "" when they all carry one
// label (or the read is unchecked).
func (s StateRead) Spread() string {
	if s.State == "" || s.Greatest == s.State {
		return ""
	}
	return "records at " + inertText(s.State) + ".." + inertText(s.Greatest) + ", read as " + inertText(s.State)
}

// ReadState reads the finality state out of a captured response under layout l, placing each record's label by
// rank (the profile's order), within steps (DefaultLayoutSteps when < 1). Every record must carry a non-empty
// string that rank places; the read is then the least record (claims-model note §5.3.1a, "Response layouts"), with
// the latest beside it. Anything else is unchecked: State "" and Why naming the first record (in array order) that
// fails and why, with no partial order over labels the profile does not have. Pure: the same bytes, layout and order
// give the same answer.
func ReadState(b []byte, l *ResponseLayout, rank LabelRank, steps int) StateRead {
	if steps < 1 {
		steps = DefaultLayoutSteps
	}
	bad := func(why string) StateRead { return StateRead{Why: why} }
	if rank == nil {
		return bad("no source profile order to place the labels by")
	}
	if len(b) > MaxResponseBytes {
		return bad(fmt.Sprintf("the response is larger than %d bytes", MaxResponseBytes))
	}
	v, err := canon.ParseData(b)
	if err != nil {
		return bad("the response is not I-JSON: " + err.Error())
	}
	if !l.HasRecords {
		s, w := stateAt(v, l, rank, -1, &steps)
		if w != "" {
			return bad(w)
		}
		return StateRead{State: s, Greatest: s}
	}
	rv, w := lookup(v, l.Records, &steps)
	if w != "" {
		return bad("records pointer " + strconv.Quote(l.RecordsText) + ": " + w)
	}
	arr, ok := rv.(canon.Array)
	if !ok {
		return bad("records pointer " + strconv.Quote(l.RecordsText) + " names a " + kindOf(rv) + ", not an array")
	}
	if len(arr) == 0 {
		return bad("the record array is empty: no state to read")
	}
	var out StateRead
	lo, hi := 0, 0
	for i, rec := range arr {
		s, w := stateAt(rec, l, rank, i, &steps)
		if w != "" {
			return bad(w)
		}
		r, _ := rank(s) // stateAt placed it
		if i == 0 || r < lo {
			out.State, lo = s, r
		}
		if i == 0 || r > hi {
			out.Greatest, hi = s, r
		}
	}
	out.Records = len(arr)
	return out
}

// stateAt reads the state pointer in v (record i, or the whole response when i < 0): a non-empty string rank
// places.
func stateAt(v canon.Value, l *ResponseLayout, rank LabelRank, i int, steps *int) (string, string) {
	where := "the response"
	if i >= 0 {
		where = "record " + strconv.Itoa(i)
		if *steps--; *steps < 0 {
			return "", LayoutStepLimit
		}
	}
	sv, w := lookup(v, l.State, steps)
	if w == LayoutStepLimit {
		return "", w
	}
	if w != "" {
		return "", where + ": state pointer " + strconv.Quote(l.StateText) + ": " + w
	}
	s, ok := sv.(canon.String)
	if !ok {
		return "", where + ": state pointer " + strconv.Quote(l.StateText) + " names a " + kindOf(sv) + ", not a string"
	}
	if s == "" {
		return "", where + ": state pointer " + strconv.Quote(l.StateText) + " names an empty string"
	}
	if _, ok := rank(string(s)); !ok {
		return "", where + " reads " + strconv.Quote(inertText(string(s))) + ", which is not in the source profile's labels: not comparable"
	}
	return string(s), ""
}

// isJSONMediaType reports whether a declared media type is JSON: application/json or a +json structured suffix
// (RFC 6839), parameters ignored, compared case-insensitively.
func isJSONMediaType(mt string) bool {
	t := strings.ToLower(strings.TrimSpace(strings.SplitN(mt, ";", 2)[0]))
	return t == "application/json" || (strings.HasSuffix(t, "+json") && strings.Contains(t, "/"))
}

// LayoutRead is what a layout read of one observation's held response found.
type LayoutRead struct {
	// Layout is the layout's digest ("" when the profile's layouts could not be used; Why says why).
	Layout string
	// State is the state read from the held bytes (the least record under the profile's order); "" when the read
	// is unchecked (Why).
	State, Why string
	// Spread discloses records that differ ("records at R1..RF, read as R1"); "" when they carry one label.
	Spread string
	// Asserted is the observer's asserted run label at capture ("" when none).
	Asserted string
}

// Disagrees reports a state read from the bytes that differs from the observer's asserted one.
func (l *LayoutRead) Disagrees() bool { return l != nil && l.State != "" && l.State != l.Asserted }

// String is the read as one line: "response layout 1a2b…: state RF read from the held response", the spread when
// records differ, the asserted state when it differs from the read one; or "…: unchecked (why)".
func (l *LayoutRead) String() string {
	name := "response layout"
	if l.Layout != "" {
		name += " " + keylog.Short(l.Layout)
	}
	if l.State == "" {
		return name + ": unchecked (" + l.Why + ")"
	}
	s := fmt.Sprintf("%s: state %s read from the held response", name, l.State)
	if l.Spread != "" {
		s += " (" + l.Spread + ")"
	}
	if l.Disagrees() {
		asserted := l.Asserted
		if asserted == "" {
			asserted = "none"
		}
		s += fmt.Sprintf("; the observer asserted %s at capture (disclosed, does not govern)", asserted)
	}
	return s
}

// BlobBytes returns a held blob's bytes up to max: nil and why when it cannot ("not held", "larger than …").
type BlobBytes func(digest string, max int64) ([]byte, string)

// ErrHeldCorrupt marks a getter's answer that the copy it holds under a digest hashes elsewhere (a getter that
// checks the hash itself, as a store does, reports it this way; a getter that returns the bytes as held leaves the
// check to AttachLayouts).
var ErrHeldCorrupt = errors.New("the held copy is corrupt (its bytes hash elsewhere)")

// AttachLayouts reads the documents a profile cites through get (as the profile itself was read: where the policy
// pinning it was read) and keeps the response layouts among them. get returns a document's bytes as held (nil when
// not held); AttachLayouts checks they hash to the cited digest. A cited document that is not held, not readable,
// or not a layout is an ordinary document. One valid layout is the profile's layout; a document that claims to be
// a layout and is not one, two layouts, or a cited document whose held copy is corrupt (which of the documents is
// the layout cannot then be read) leave the profile's layout unusable, naming why (never picked by order).
func (p *SourceProfile) AttachLayouts(get func(d string) ([]byte, error)) {
	var found []*ResponseLayout
	for _, d := range p.Documents {
		if !reDigestForm.MatchString(d) {
			continue
		}
		b, err := get(d)
		if errors.Is(err, ErrHeldCorrupt) || (err == nil && b != nil && digestOf(b) != d) {
			p.layoutWhy = "document " + keylog.Short(d) + " is held corrupt (its bytes hash elsewhere), so whether it is the profile's " +
				ResponseLayoutTag + " layout cannot be read; refetch it"
			p.Layout = nil
			return
		}
		if err != nil || b == nil || !IsResponseLayout(b) {
			continue
		}
		l, err := ParseResponseLayout(b)
		if err != nil {
			p.layoutWhy = "document " + keylog.Short(d) + " is not a " + ResponseLayoutTag + " layout: " + err.Error()
			p.Layout = nil
			return
		}
		found = append(found, l)
	}
	switch len(found) {
	case 0:
	case 1:
		p.Layout = found[0]
	default:
		p.layoutWhy = fmt.Sprintf("the profile cites %d response layouts; none is picked", len(found))
	}
}

// Rank places a label in the profile's order (a LabelRank): its index, earliest state first, and whether the
// profile has it. An integer-depth profile has no labels.
func (p *SourceProfile) Rank(label string) (int, bool) {
	i, ok := p.index[label]
	return i, ok
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HasLayout reports whether the profile cites a response layout (usable or not).
func (p *SourceProfile) HasLayout() bool { return p.Layout != nil || p.layoutWhy != "" }

// readLayout reads the run label out of an observation's held response under the bound profile's layout. nil when
// the profile cites no layout, or the rule is not an ordered-label rule under it: the asserted state is read exactly
// as without a layout. body is the `observed` statement body.
func (b BoundRules) readLayout(rule string, body *canon.Object, asserted State) *LayoutRead {
	p := b.Profile
	if p == nil || !p.HasLayout() || p.Dialect != DialectOrderedLabel || !reLabelRule.MatchString(rule) {
		return nil
	}
	lr := &LayoutRead{Asserted: asserted.Run}
	if p.Layout == nil {
		lr.Why = p.layoutWhy
		return lr
	}
	lr.Layout = p.Layout.Digest
	ref := object(body, "referent")
	rd := str(ref, "response_digest")
	switch {
	case str(body, "class") != "source":
		lr.Why = "a response layout reads a source-class capture, this is " + inertText(str(body, "class"))
		return lr
	case rd == "":
		lr.Why = "the referent pins no single response_digest (a batch capture is not read)"
		return lr
	}
	if mt := str(object(body, "content"), "media_type"); mt != "" && !isJSONMediaType(mt) {
		lr.Why = "the capture's media type " + strconv.Quote(inertText(mt)) + " is not JSON; this layout dialect reads JSON only"
		return lr
	}
	if sr, ok := b.reads.get(p.Digest, p.Layout.Digest, rd); ok {
		lr.State, lr.Why, lr.Spread = sr.State, sr.Why, sr.Spread()
		return lr
	}
	if b.bytes == nil {
		lr.Why = "response " + keylog.Short(rd) + " not held"
		return lr
	}
	data, why := b.bytes(rd, MaxResponseBytes)
	if data == nil {
		if why == "" {
			why = "not held"
		}
		lr.Why = "response " + keylog.Short(rd) + " " + why
		b.reads.put(p.Digest, p.Layout.Digest, rd, StateRead{Why: lr.Why})
		return lr
	}
	sr := ReadState(data, p.Layout, p.Rank, b.steps)
	lr.State, lr.Why, lr.Spread = sr.State, sr.Why, sr.Spread()
	b.reads.put(p.Digest, p.Layout.Digest, rd, sr)
	return lr
}

// layoutCache keeps each layout read by (profile, layout, response): a read is a pure function of the response
// bytes, the layout and the profile's label order (which the profile's digest fixes), so a response is parsed once
// per reader however many views and comparisons ask (the bytes behind a digest never change; a store whose copy is
// corrupt holds nothing under it).
type layoutCache struct {
	mu sync.Mutex
	m  map[[3]string]StateRead
}

func (c *layoutCache) get(profile, layout, response string) (StateRead, bool) {
	if c == nil {
		return StateRead{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[[3]string{profile, layout, response}]
	return v, ok
}

func (c *layoutCache) put(profile, layout, response string, sr StateRead) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m[[3]string{profile, layout, response}] = sr
	c.mu.Unlock()
}

// heldState is the state a capture q is read at under rules for rule: the state its held response gives under the
// bound profile's response layout when that read succeeds (the read state governs, claims-model note §5.3.1a), else
// the asserted state at capture exactly as without a layout. lr is the layout read (nil when no layout applies).
func heldState(rules FinalityRules, rule string, q *canon.Object, asserted State) (State, *LayoutRead) {
	b, ok := rules.(BoundRules)
	if !ok {
		return asserted, nil
	}
	lr := b.readLayout(rule, q, asserted)
	if lr == nil || lr.State == "" {
		return asserted, lr
	}
	return State{Run: lr.State}, lr
}
