package resolve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
// Reading a state is a pure function of the held response bytes and the layout: every record must carry the same
// non-empty string at the state pointer. Anything else (records that disagree, a pointer that names nothing, a
// value that is not a string, bytes that are not I-JSON, a response that is not held or exceeds the caps) reads
// `unchecked`, naming why, and the observer's asserted state is used exactly as without a layout, never upgraded.

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

// ReadState reads the finality state out of a captured response under layout l, within steps (DefaultLayoutSteps
// when < 1). It returns the state when every record agrees on one non-empty string, else "" and why. Pure: the same
// bytes and layout give the same answer.
func ReadState(b []byte, l *ResponseLayout, steps int) (state, why string) {
	if steps < 1 {
		steps = DefaultLayoutSteps
	}
	if len(b) > MaxResponseBytes {
		return "", fmt.Sprintf("the response is larger than %d bytes", MaxResponseBytes)
	}
	v, err := canon.ParseData(b)
	if err != nil {
		return "", "the response is not I-JSON: " + err.Error()
	}
	if !l.HasRecords {
		return stateAt(v, l, -1, &steps)
	}
	rv, w := lookup(v, l.Records, &steps)
	if w != "" {
		return "", "records pointer " + strconv.Quote(l.RecordsText) + ": " + w
	}
	arr, ok := rv.(canon.Array)
	if !ok {
		return "", "records pointer " + strconv.Quote(l.RecordsText) + " names a " + kindOf(rv) + ", not an array"
	}
	if len(arr) == 0 {
		return "", "the record array is empty: no state to read"
	}
	first := -1
	for i, rec := range arr {
		s, w := stateAt(rec, l, i, &steps)
		if w != "" {
			return "", w
		}
		if first < 0 {
			state, first = s, i
			continue
		}
		if s != state {
			return "", fmt.Sprintf("records disagree: record %d reads %q, record %d reads %q", first, inertText(state), i, inertText(s))
		}
	}
	return state, ""
}

// stateAt reads the state pointer in v (record i, or the whole response when i < 0).
func stateAt(v canon.Value, l *ResponseLayout, i int, steps *int) (string, string) {
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
	// State is the state read from the held bytes; "" when the read is unchecked (Why).
	State, Why string
	// Asserted is the observer's asserted run label at capture ("" when none).
	Asserted string
}

// Disagrees reports a state read from the bytes that differs from the observer's asserted one.
func (l *LayoutRead) Disagrees() bool { return l != nil && l.State != "" && l.State != l.Asserted }

// String is the read as one line: "RF from the held response (layout 1a2b…)" or "unchecked (why)".
func (l *LayoutRead) String() string {
	name := "response layout"
	if l.Layout != "" {
		name += " " + keylog.Short(l.Layout)
	}
	if l.State == "" {
		return name + ": unchecked (" + l.Why + ")"
	}
	s := fmt.Sprintf("%s: state %s read from the held response", name, l.State)
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

// AttachLayouts reads the documents a profile cites through get (as the profile itself was read: where the policy
// pinning it was read) and keeps the response layouts among them. A cited document that is not held, not readable,
// or not a layout is an ordinary document. One valid layout is the profile's layout; a document that claims to be
// a layout and is not one, or two layouts, leave the profile's layout unusable, naming why (never picked by order).
func (p *SourceProfile) AttachLayouts(get func(d string) ([]byte, error)) {
	var found []*ResponseLayout
	for _, d := range p.Documents {
		if !reDigestForm.MatchString(d) {
			continue
		}
		b, err := get(d)
		if err != nil || b == nil || !IsResponseLayout(b) {
			continue
		}
		l, err := ParseResponseLayout(b)
		if err != nil {
			p.layoutWhy = "document " + keylog.Short(d) + " is not a " + ResponseLayoutTag + " layout: " + err.Error()
			p.Layout = nil
			return
		}
		if l.Digest != d {
			continue // the getter returned other bytes; never used under another name
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
	if st, why, ok := b.reads.get(p.Layout.Digest, rd); ok {
		lr.State, lr.Why = st, why
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
		b.reads.put(p.Layout.Digest, rd, "", lr.Why)
		return lr
	}
	lr.State, lr.Why = ReadState(data, p.Layout, b.steps)
	if _, ok := p.index[lr.State]; lr.State != "" && !ok {
		// a label the profile cannot place is not a state this reader reads by (claims-model note §5.3.1a)
		lr.State, lr.Why = "", fmt.Sprintf("the records agree on %q, which is not in source profile %s: not comparable", inertText(lr.State), keylog.Short(p.Digest))
	}
	b.reads.put(p.Layout.Digest, rd, lr.State, lr.Why)
	return lr
}

// layoutCache keeps each layout read by (layout, response): a read is a pure function of the two digests, so a
// response is parsed once per reader however many views and comparisons ask (the bytes behind a digest never
// change; a store whose copy is corrupt holds nothing under it).
type layoutCache struct {
	mu sync.Mutex
	m  map[[2]string][2]string
}

func (c *layoutCache) get(layout, response string) (state, why string, ok bool) {
	if c == nil {
		return "", "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[[2]string{layout, response}]
	return v[0], v[1], ok
}

func (c *layoutCache) put(layout, response, state, why string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m[[2]string{layout, response}] = [2]string{state, why}
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
